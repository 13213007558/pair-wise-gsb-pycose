import abc
from typing import List, Optional, TypeVar, Type, TYPE_CHECKING

import cbor2

from pycose import headers
from pycose.exceptions import CoseInvalidKey
from pycose.keys import CoseKey
from pycose.keys.ec2 import EC2Key
from pycose.keys.okp import OKPKey
from pycose.keys.rsa import RSAKey
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.cosebase import CoseBase

if TYPE_CHECKING:
    from pycose.messages.countersignature import Countersignature, Countersignature0

CBOR = bytes


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
    def countersignatures(self) -> List['Countersignature']:
        """
        Parse the RFC 9338 CounterSignatureV2 header parameter into a list of
        Countersignature objects bound to this message.

        The deprecated RFC 8152 countersignature header parameters (CounterSignature and
        CounterSignature0) are not interpreted as version 2 countersignatures.

        :returns: A list of Countersignature objects (empty when the header parameter is absent).
        """

        from pycose.messages.countersignature import Countersignature

        raw = self._uhdr.get(headers.CounterSignatureV2)
        if raw is None:
            return []

        # be lenient and also accept a single (non-array wrapped) COSE_Countersignature structure
        if isinstance(raw, list) and len(raw) == 3 and isinstance(raw[0], bytes):
            raw = [raw]

        parsed = []
        for entry in raw:
            cs = Countersignature.from_cose_obj(list(entry), allow_unknown_attributes=True)
            cs._parent = self
            parsed.append(cs)

        return parsed

    @property
    def countersignature0(self) -> Optional['Countersignature0']:
        """
        Parse the RFC 9338 CounterSignature0V2 header parameter into a Countersignature0
        object bound to this message.

        :returns: A Countersignature0 object or None when the header parameter is absent.
        """

        from pycose.messages.countersignature import Countersignature0

        signature = self._uhdr.get(headers.CounterSignature0V2)
        if signature is None:
            return None

        cs0 = Countersignature0(signature=signature)
        cs0._parent = self
        return cs0

    def countersign(self,
                    key: CoseKey,
                    protected: Optional[dict] = None,
                    unprotected: Optional[dict] = None,
                    detached_payload: Optional[bytes] = None) -> 'Countersignature':
        """
        Create an RFC 9338 countersignature over this message and attach it to the unprotected
        header under the CounterSignatureV2 (11) header parameter.

        :param key: The COSE key used to compute the countersignature.
        :param protected: Protected header bucket of the countersignature (should carry the algorithm).
        :param unprotected: Unprotected header bucket of the countersignature.
        :param detached_payload: Optional detached payload of the countersigned message.
        :returns: The created Countersignature object.
        """

        from pycose.messages.countersignature import Countersignature

        cs = Countersignature(phdr=protected, uhdr=unprotected, key=key)
        cs._parent = self
        cs.signature = cs.compute_signature(detached_payload)

        encoded = cs.encode()
        existing = self._uhdr.get(headers.CounterSignatureV2)
        if existing is None:
            self._uhdr[headers.CounterSignatureV2] = [encoded]
        elif isinstance(existing, list) and len(existing) > 0 and isinstance(existing[0], list):
            existing.append(encoded)
        else:
            # a single (non-array wrapped) COSE_Countersignature structure was present
            self._uhdr[headers.CounterSignatureV2] = [existing, encoded]

        return cs

    def countersign0(self, key: CoseKey, detached_payload: Optional[bytes] = None) -> bytes:
        """
        Create an RFC 9338 CounterSignature0V2 signature over this message and attach it to the
        unprotected header under the CounterSignature0V2 (12) header parameter.

        :param key: The COSE key used to compute the countersignature (must carry an algorithm).
        :param detached_payload: Optional detached payload of the countersigned message.
        :returns: The computed signature.
        """

        from pycose.messages.countersignature import Countersignature0

        cs0 = Countersignature0(key=key)
        cs0._parent = self
        signature = cs0.compute_signature(detached_payload)

        self._uhdr[headers.CounterSignature0V2] = signature

        return signature

    def verify_countersignatures(self, key: CoseKey, detached_payload: Optional[bytes] = None) -> bool:
        """
        Verify all RFC 9338 countersignatures attached to this message (both CounterSignatureV2 and
        CounterSignature0V2 header parameters) with the provided key.

        The message is never modified by the verification: countersignatures that fail verification
        remain attached to the message and the message object stays fully inspectable.

        :param key: The COSE key used to verify the countersignatures.
        :param detached_payload: Optional detached payload of the countersigned message.
        :returns: True when at least one countersignature is present and all of them verify,
            False otherwise.
        """

        found = False
        valid = True

        for cs in self.countersignatures:
            found = True
            cs.key = key
            try:
                ok = cs.verify_signature(detached_payload)
            except Exception:
                ok = False
            valid = valid and ok

        cs0 = self.countersignature0
        if cs0 is not None:
            found = True
            cs0.key = key
            try:
                ok = cs0.verify_signature(detached_payload)
            except Exception:
                ok = False
            valid = valid and ok

        return found and valid

    def _base_structure(self, structure: list) -> list:
        if len(self.phdr) == 0:
            structure.append(b'')
        else:
            structure.append(self.phdr_encoded)

        structure.append(self._external_aad)

        return structure


CM = TypeVar('CM', bound=CoseMessage)
