import abc
from typing import Optional, TypeVar, Type, List, TYPE_CHECKING

import cbor2

from pycose import headers
from pycose.exceptions import CoseInvalidKey, CoseException, CoseMalformedMessage
from pycose.keys import CoseKey
from pycose.keys.ec2 import EC2Key
from pycose.keys.okp import OKPKey
from pycose.keys.rsa import RSAKey
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.cosebase import CoseBase

CBOR = bytes

if TYPE_CHECKING:
    from pycose.messages.countersignature import CounterSignature0V2Message, CounterSignatureV2Message


class CoseMessage(CoseBase, metaclass=abc.ABCMeta):
    """ Parent class of all COSE message types. """

    # private dictionary to record all COSE message types dynamically
    _COSE_MSG_ID = {}

    @classmethod
    def record_cbor_tag(cls, cbor_tag: int):
        """ Decorator to record all the CBOR tags dynamically. """

        def decorator(the_class):
            if not issubclass(the_class, CoseMessage):
                raise ValueError("Can only decorate subclass of CoseMessage")
            cls._COSE_MSG_ID[cbor_tag] = the_class
            return the_class

        return decorator

    @classmethod
    def decode(cls: Type['CM'], received: bytes, *args, **kwargs) -> 'CM':
        """
        Decode received COSE message based on the CBOR tag.

        If called on CoseMessage, this function can decode any supported
        message type. Otherwise, if called on a sub-class of CoseMessage,
        only messages of that type will be allowed to be decoded.

        :param received: COSE messages encoded as bytes

        :raises AttributeError: When the COSE message, it cannot be decoded properly
        :raises ValueError: The received parameter must be bytes
        :raises KeyError: thrown when the CBOR tag, identifying the COSE message is unrecognized
        :raises TypeError: thrown when the messages cannot be decoded properly
        :raises TypeError: The message's tag does not match the expected type.
        :returns: An initialized CoseMessage
        """

        try:
            cbor_msg = cbor2.loads(received)
            cbor_tag = cbor_msg.tag
            cose_obj = cbor_msg.value
        except AttributeError:
            raise AttributeError("Message was not tagged.")
        except ValueError:
            raise ValueError("Decode accepts only bytes as input.")

        if isinstance(cose_obj, list):
            try:
                decoded = cls._COSE_MSG_ID[cbor_tag].from_cose_obj(cose_obj, kwargs.get("allow_unknown_attributes", True))
            except KeyError as e:
                raise KeyError("CBOR tag is not recognized", e)

            if not isinstance(decoded, cls):
                raise TypeError(f"CBOR tag {cbor_tag} does not match the expected message type {cls.__name__}.")

            return decoded
        else:
            raise TypeError("Bytes cannot be decoded as COSE message")

    @classmethod
    def from_cose_obj(cls: Type['CM'], cose_obj: list, allow_unknown_attributes: bool) -> 'CM':
        """ Internal function that returns an initialized COSE message object. """

        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg.payload = cose_obj.pop(0)
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: Optional[bytes] = None,
                 external_aad: bytes = b'',
                 key: Optional[CoseKey] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr, uhdr, *args, **kwargs)

        self.payload = payload
        self.external_aad = external_aad
        self.key = key

    @property
    def external_aad(self) -> bytes:
        return self._external_aad

    @property
    @abc.abstractmethod
    def cbor_tag(self):
        raise NotImplementedError()

    @external_aad.setter
    def external_aad(self, new_external_aad: bytes) -> None:
        if type(new_external_aad) is not bytes:
            raise TypeError("external_aad must be of type 'bytes'")
        self._external_aad = new_external_aad

    @property
    def key(self) -> CoseKey:
        return self._key

    @key.setter
    def key(self, key: Optional[CoseKey]):
        if not isinstance(key, SymmetricKey) and \
                not isinstance(key, EC2Key) and \
                not isinstance(key, OKPKey) and \
                not isinstance(key, RSAKey) and \
                key is not None:

            raise CoseInvalidKey(f"Unknown key type: {type(key)}")
        else:
            self._key = key

    @property
    def payload(self) -> Optional[bytes]:
        return self._payload

    @payload.setter
    def payload(self, new_payload: Optional[bytes]) -> None:
        if new_payload is not None and type(new_payload) is not bytes:
            raise TypeError("payload should be of type 'bytes' not {}".format(type(new_payload)))
        self._payload = new_payload  # can be plaintext or ciphertext

    @abc.abstractmethod
    def encode(self, message: list, tag: bool = True, *args, **kwargs) -> CBOR:
        if tag:
            message = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._custom_cbor_encoder)
        else:
            message = cbor2.dumps(message, default=self._custom_cbor_encoder)

        return message

    @property
    def countersignatures(self) -> List['CounterSignatureV2Message']:
        return self._get_countersignatures()

    @property
    def counter_signatures_v2(self) -> List['CounterSignatureV2Message']:
        return self.countersignatures

    def _get_countersignatures(self, allow_unknown_attributes: bool = True) -> List['CounterSignatureV2Message']:
        from pycose.messages.countersignature import CounterSignatureV2Message as CountersignatureV2

        raw = self._uhdr.get(headers.CounterSignatureV2)
        if raw is None:
            return []

        if not isinstance(raw, list) or not raw:
            raise CoseMalformedMessage("CounterSignatureV2 must be a non-empty array")

        entries = raw
        countersignatures = []
        for entry in entries:
            self._validate_countersignature_entry(entry)
            cs = CountersignatureV2.from_cose_obj(list(entry), allow_unknown_attributes)
            cs._parent = self
            countersignatures.append(cs)

        return countersignatures

    @property
    def counter_signature0_v2(self) -> Optional['CounterSignature0V2Message']:
        return self._get_counter_signature0_v2()

    @property
    def countersignature0_v2(self) -> Optional['CounterSignature0V2Message']:
        return self.counter_signature0_v2

    def _get_counter_signature0_v2(self,
                                   allow_unknown_attributes: bool = True) -> Optional['CounterSignature0V2Message']:
        from pycose.messages.countersignature import CounterSignature0V2Message

        raw = self._uhdr.get(headers.CounterSignature0V2)
        if raw is None:
            return None

        if not isinstance(raw, bytes):
            raise CoseMalformedMessage("CounterSignature0V2 must be a bstr-wrapped COSE_Sign1 structure")

        encoded_message = cbor2.loads(raw)
        self._validate_countersignature0_entry(encoded_message)
        cs0 = CounterSignature0V2Message.from_cose_obj(list(encoded_message), allow_unknown_attributes)
        cs0._parent = self
        return cs0

    def countersign(self,
                    key: 'CoseKey',
                    protected: Optional[dict] = None,
                    unprotected: Optional[dict] = None,
                    detached_payload: Optional[bytes] = None) -> 'CounterSignatureV2Message':
        from pycose.messages.countersignature import CounterSignatureV2Message as CountersignatureV2

        cs = CountersignatureV2(phdr=protected, uhdr=unprotected, key=key)
        cs._parent = self
        cs.signature = cs.compute_signature(detached_payload)

        existing = self._uhdr.get(headers.CounterSignatureV2)
        encoded = cs.encode()
        if existing is None:
            self._uhdr[headers.CounterSignatureV2] = [encoded]
        elif isinstance(existing, list) and existing:
            existing.append(encoded)
        else:
            raise CoseMalformedMessage("CounterSignatureV2 must be a non-empty array")

        return cs

    def countersign0(self,
                     key: 'CoseKey',
                     protected: Optional[dict] = None,
                     unprotected: Optional[dict] = None,
                     detached_payload: Optional[bytes] = None) -> 'CounterSignature0V2Message':
        from pycose.messages.countersignature import CounterSignature0V2Message

        cs0 = CounterSignature0V2Message(phdr=protected, uhdr=unprotected, key=key)
        cs0._parent = self
        cs0.signature = cs0.compute_signature(detached_payload)

        self._uhdr[headers.CounterSignature0V2] = cs0.encode()
        return cs0

    def verify_countersignatures(self,
                                 key: Optional['CoseKey'] = None,
                                 detached_payload: Optional[bytes] = None,
                                 allow_unknown_attributes: bool = True) -> bool:
        found = False
        valid = True

        for cs in self._get_countersignatures(allow_unknown_attributes):
            found = True
            if key is not None:
                cs.key = key
            try:
                valid = cs.verify_signature(detached_payload) and valid
            except Exception:
                valid = False

        cs0 = self._get_counter_signature0_v2(allow_unknown_attributes)
        if cs0 is not None:
            found = True
            if key is not None:
                cs0.key = key
            try:
                valid = cs0.verify_signature(detached_payload) and valid
            except Exception:
                valid = False

        return found and valid

    @staticmethod
    def _validate_countersignature_entry(entry) -> None:
        if not isinstance(entry, list) or len(entry) != 3:
            raise CoseMalformedMessage("CounterSignatureV2 entries must contain protected, unprotected, and signature")
        if not isinstance(entry[0], bytes) or not isinstance(entry[1], dict) or not isinstance(entry[2], bytes):
            raise CoseMalformedMessage("Malformed CounterSignatureV2 entry")

    @staticmethod
    def _validate_countersignature0_entry(entry) -> None:
        if not isinstance(entry, list) or len(entry) != 4:
            raise CoseMalformedMessage("CounterSignature0V2 must wrap a COSE_Sign1 structure")
        if not isinstance(entry[0], bytes) or not isinstance(entry[1], dict) or entry[2] != b'' \
                or not isinstance(entry[3], bytes):
            raise CoseMalformedMessage("Malformed CounterSignature0V2 structure")

    def _base_structure(self, structure: list) -> list:
        if len(self.phdr) == 0:
            structure.append(b'')
        else:
            structure.append(self.phdr_encoded)

        structure.append(self._external_aad)

        return structure


CM = TypeVar('CM', bound=CoseMessage)
