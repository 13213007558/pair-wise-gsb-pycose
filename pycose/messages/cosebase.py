import abc
from copy import deepcopy
from typing import Optional, Any, Dict, List, Type, Tuple, TypeVar, TYPE_CHECKING

import cbor2

from pycose import utils
from pycose.algorithms import CoseAlgorithm
from pycose.exceptions import CoseException, CoseMalformedMessage
from pycose.headers import CoseHeaderAttribute, Algorithm, CounterSignatureV2, CounterSignature0V2
from pycose.keys.cosekey import CoseKey
from pycose.keys.cosekey import KpKeyOps

if TYPE_CHECKING:
    from pycose.messages.countersignature import CoseCounterSignatureBase

CBOR = bytes


class CoseBase(metaclass=abc.ABCMeta):
    """ Basic COSE information buckets. """

    @classmethod
    def from_cose_obj(cls: Type['CB'], cose_obj: list, allow_unknown_attributes: bool) -> 'CB':
        phdr_encoded = cose_obj.pop(0)
        uhdr = cose_obj.pop(0)

        return cls(phdr_encoded=phdr_encoded, uhdr=uhdr, allow_unknown_attributes=allow_unknown_attributes)

    def __init__(self, phdr: Optional[dict] = None, uhdr: Optional[dict] = None, payload: Optional[bytes] = None, phdr_encoded: Optional[bytes] = None, *args, **kwargs):
        if phdr is not None and phdr_encoded is not None:
            raise ValueError("Cannot have both phdr and phdr_encoded")
        
        if phdr_encoded is not None:
            if phdr_encoded == b"":
                phdr = {}
            else:
                phdr = cbor2.loads(phdr_encoded)
        elif phdr is None:
            phdr = {}

        if uhdr is None:
            uhdr = {}

        if type(phdr) is not dict:
            raise TypeError("protected header should be of type 'dict'")

        if type(uhdr) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")

        self._local_attrs = {}

        self.alg_tstr_encoding = kwargs.get("alg_tstr_encoding", False)

        self._phdr_encoded = phdr_encoded
        self._phdr = CoseBase._parse_header(phdr, kwargs.get("allow_unknown_attributes", True))
        self._uhdr = CoseBase._parse_header(uhdr, kwargs.get("allow_unknown_attributes", True))
        self._decode_countersignatures()

        # can be plaintext or ciphertext
        if payload is not None and type(payload) is not bytes:
            raise TypeError("payload should be of type 'bytes'")
        self._payload = payload

    def _decode_countersignatures(self) -> None:
        """
        Convert the raw values of the RFC 9338 countersignature header attributes in the
        unprotected header bucket into countersignature objects bound to this structure.

        The legacy (RFC 8152) COUNTER_SIGN and COUNTER_SIGN0 attributes are left untouched.
        """

        from pycose.messages.countersignature import CoseCounterSignature, CoseCounterSignature0

        if CounterSignatureV2 in self._uhdr:
            self._uhdr[CounterSignatureV2] = self._to_countersignature(self._uhdr[CounterSignatureV2],
                                                                       CoseCounterSignature)

        if CounterSignature0V2 in self._uhdr:
            self._uhdr[CounterSignature0V2] = self._to_countersignature(self._uhdr[CounterSignature0V2],
                                                                        CoseCounterSignature0)

    def _to_countersignature(self, value: Any, cs_class: type) -> Any:
        from pycose.messages.countersignature import CoseCounterSignature, CoseCounterSignature0

        if cs_class is CoseCounterSignature0:
            if isinstance(value, CoseCounterSignature0):
                countersignature = value
            elif isinstance(value, bytes):
                countersignature = CoseCounterSignature0(signature=value)
            else:
                raise CoseMalformedMessage("COUNTER_SIGN0_V2 attribute must carry a byte string")
        else:
            if isinstance(value, CoseCounterSignature):
                countersignature = value
            elif isinstance(value, list) and len(value) == 3 and isinstance(value[0], bytes):
                # a single COSE_Countersignature structure
                countersignature = CoseCounterSignature.from_cose_obj(value, allow_unknown_attributes=True)
            elif isinstance(value, list):
                # an array of COSE_Countersignature structures
                return [self._to_countersignature(v, cs_class) for v in value]
            else:
                raise CoseMalformedMessage("COUNTER_SIGN_V2 attribute must carry a COSE_Countersignature "
                                           "structure or an array of structures")

        countersignature._parent = self
        return countersignature

    def _encode_countersignatures(self, value: Any) -> Any:
        from pycose.messages.countersignature import CoseCounterSignatureBase

        if isinstance(value, CoseCounterSignatureBase):
            if value._parent is None:
                value._parent = self
            return value.encode()
        elif isinstance(value, list):
            return [self._encode_countersignatures(v) for v in value]
        else:
            return value

    @property
    def countersignatures(self) -> List['CoseCounterSignatureBase']:
        """
        All RFC 9338 countersignatures carried in the unprotected header bucket.

        :returns: A list of CoseCounterSignature and/or CoseCounterSignature0 objects.
        """

        result = []

        value = self._uhdr.get(CounterSignatureV2)
        if value is not None:
            result.extend(value if isinstance(value, list) else [value])

        value = self._uhdr.get(CounterSignature0V2)
        if value is not None:
            result.append(value)

        return result

    def verify_countersignature(self,
                                countersignature: 'CoseCounterSignatureBase',
                                detached_payload: Optional[bytes] = None) -> bool:
        """
        Verify an RFC 9338 countersignature attached to this COSE object.

        A failed verification does not modify the object: the countersignature stays in
        place and the object remains available for further inspection.

        :param countersignature: A countersignature object carried by this COSE object.
        :param detached_payload: The detached payload of the countersigned structure, if any.

        :raises CoseException: When the countersignature is not attached to this object.
        :returns: True for a valid countersignature or False for an invalid countersignature.
        """

        if countersignature not in self.countersignatures:
            raise CoseException("Countersignature is not attached to this COSE object")

        return countersignature.verify_signature(detached_payload=detached_payload)

    def get_attr(self, attribute: Type[CoseHeaderAttribute], default: Any = None) -> Optional[Any]:
        """
        Fetches an header attribute from the COSE header buckets.

        :param attribute: A header parameter to fetch from the buckets.
        :param default: A default return value in case the attribute was not found

        :raise CoseException: When the same attribute is found in both the protected and unprotected header.
        :returns: If found returns a header attribute else 'None' or the default value
        """

        p_attr = self._phdr.get(attribute, default)
        u_attr = self._uhdr.get(attribute, default)

        if p_attr is not None and u_attr is not None:
            raise CoseException("MALFORMED: different values for the same header parameters in the header buckets")

        if p_attr is not None:
            return p_attr
        else:
            return u_attr

    @property
    def phdr(self) -> dict:
        return self._phdr

    @phdr.setter
    def phdr(self, new_phdr: dict) -> None:
        if type(new_phdr) is not dict:
            raise TypeError("protected header should be of type 'dict'")
        self._phdr = deepcopy(new_phdr)
        self._phdr_encoded = None

    @property
    def uhdr(self) -> dict:
        return self._uhdr

    @uhdr.setter
    def uhdr(self, new_uhdr: dict) -> None:
        if type(new_uhdr) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")
        self._uhdr = deepcopy(new_uhdr)

    def phdr_update(self, phdr_params: dict) -> None:
        if type(phdr_params) is not dict:
            raise TypeError("protected header should be of type 'dict'")
        self._phdr.update(phdr_params)
        self._phdr_encoded = None

    def uhdr_update(self, uhdr_params: dict) -> None:
        if type(uhdr_params) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")
        self._uhdr.update(uhdr_params)
        self._decode_countersignatures()

    @property
    def local_attrs(self):
        return self._local_attrs

    @local_attrs.setter
    def local_attrs(self, attributes: Dict['CoseHeaderAttribute', Any]):
        for k, v in attributes.items():
            self._local_attrs[k] = v

    @property
    def phdr_encoded(self) -> CBOR:
        """
        Encode the protected header.

        :returns: Returns the encoded protected header.
        """

        if self._phdr_encoded is not None:
            return self._phdr_encoded
        # TODO: check if not double header parameters in header buckets
        if len(self._phdr):
            return cbor2.dumps(self._phdr, default=self._custom_cbor_encoder)
        else:
            return b''

    @property
    def uhdr_encoded(self) -> dict:
        """
        Encode the unprotected header.

        :returns: Returns the encoded unprotected header.
        """

        # TODO: check if not double header parameters in header buckets
        uhdr = {}
        for k, v in self._uhdr.items():
            if k is CounterSignatureV2 or k is CounterSignature0V2:
                uhdr[k] = self._encode_countersignatures(v)
            else:
                uhdr[k] = v

        return uhdr

    def _custom_cbor_encoder(self, encoder, cose_attribute: Type['CoseHeaderAttribute']):
        if isinstance(cose_attribute, CoseKey):
            new_dict = dict(cose_attribute)
            if KpKeyOps in new_dict and not len(new_dict[KpKeyOps]):
                del new_dict[KpKeyOps]
            encoder.encode(new_dict)
        elif issubclass(cose_attribute, CoseAlgorithm) and self.alg_tstr_encoding:
            encoder.encode(cose_attribute.fullname)
        else:
            encoder.encode(cose_attribute.identifier)

    @classmethod
    def _parse_header(cls, hdr, allow_unknown_attributes: bool) -> dict:
        decoded_hdr = {}
        for k, v in hdr.items():
            attr = CoseHeaderAttribute.from_id(k, allow_unknown_attributes)

            if hasattr(attr, 'value_parser'):
                decoded_hdr[attr] = attr.value_parser(v)
            else:
                decoded_hdr[attr] = v

        return decoded_hdr

    def _hdr_repr(self) -> Tuple[dict, dict]:
        phdr = {(k.__name__ if hasattr(k, '__name__') else k): (
            self._phdr[k].__name__ if hasattr(self._phdr[k], '__name__') else self._phdr[k]) for k in self._phdr}

        uhdr = {(k.__name__ if hasattr(k, '__name__') else k): (
            self._uhdr[k].__name__ if hasattr(self._uhdr[k], '__name__') else self._uhdr[k]) for k in self._uhdr}

        if 'IV' in phdr and len(phdr['IV']) > 0:
            phdr['IV'] = utils.truncate(phdr['IV'])

        if 'IV' in uhdr and len(uhdr['IV']) > 0:
            uhdr['IV'] = utils.truncate(uhdr['IV'])

        if 'PARTIAL_IV' in phdr and len(phdr['PARTIAL_IV']) > 0:
            phdr['PARTIAL_IV'] = utils.truncate(phdr['PARTIAL_IV'])

        if 'PARTIAL_IV' in uhdr and len(uhdr['PARTIAL_IV']) > 0:
            uhdr['PARTIAL_IV'] = utils.truncate(uhdr['PARTIAL_IV'])

        return phdr, uhdr

CB = TypeVar('CB', bound=CoseBase)
