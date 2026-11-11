import abc
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Optional, Any, Dict, Type, Tuple, TypeVar

import cbor2

from pycose import utils
from pycose.algorithms import CoseAlgorithm
from pycose.exceptions import CoseException
from pycose.headers import CoseHeaderAttribute, Algorithm
from pycose.keys.cosekey import CoseKey
from pycose.keys.cosekey import KpKeyOps

CBOR = bytes


class _FrozenHeaderDict(Mapping):
    """ Read-only view over a COSE header bucket. """

    __slots__ = ('_data',)

    def __init__(self, data: dict):
        self._data = data

    def __getitem__(self, key):
        return _freeze_header_value(self._data[key])

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __eq__(self, other):
        if isinstance(other, _FrozenHeaderDict):
            other = other._data
        return self._data == other

    def __repr__(self):
        return repr(self._data)


class _FrozenHeaderList(Sequence):
    """ Read-only view over a mutable sequence stored in a COSE header bucket. """

    __slots__ = ('_data',)

    def __init__(self, data):
        self._data = data

    def __getitem__(self, index):
        return _freeze_header_value(self._data[index])

    def __len__(self):
        return len(self._data)

    def __eq__(self, other):
        if isinstance(other, _FrozenHeaderList):
            other = other._data
        if isinstance(other, (list, tuple)):
            return list(self._data) == list(other)
        return NotImplemented

    def __repr__(self):
        return repr(self._data)


def _freeze_header_value(value: Any) -> Any:
    """ Recursively wrap mutable header values in read-only views. """

    if isinstance(value, CoseKey):
        # COSE keys are live key objects (e.g. ephemeral keys transported in a header)
        return value
    if isinstance(value, dict):
        return _FrozenHeaderDict(value)
    if isinstance(value, (list, tuple)):
        return _FrozenHeaderList(value)
    return value


def _thaw_header_value(value: Any) -> Any:
    """ Recursively replace read-only header views by plain mutable containers. """

    if isinstance(value, CoseKey):
        return value
    if isinstance(value, _FrozenHeaderDict):
        return {k: _thaw_header_value(v) for k, v in value._data.items()}
    if isinstance(value, _FrozenHeaderList):
        return [_thaw_header_value(v) for v in value._data]
    if isinstance(value, dict):
        return {k: _thaw_header_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_header_value(v) for v in value]
    return value


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

        # copy the caller-provided buckets so later (nested) mutations of the
        # original objects cannot desynchronize the cached phdr_encoded bytes
        phdr = deepcopy(phdr)
        uhdr = deepcopy(uhdr)

        self._local_attrs = {}

        self.alg_tstr_encoding = kwargs.get("alg_tstr_encoding", False)

        self._phdr_encoded = phdr_encoded
        self._phdr = CoseBase._parse_header(phdr, kwargs.get("allow_unknown_attributes", True))
        self._uhdr = CoseBase._parse_header(uhdr, kwargs.get("allow_unknown_attributes", True))

        # can be plaintext or ciphertext
        if payload is not None and type(payload) is not bytes:
            raise TypeError("payload should be of type 'bytes'")
        self._payload = payload

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
            return _freeze_header_value(p_attr)
        else:
            return _freeze_header_value(u_attr)

    @property
    def phdr(self) -> Mapping:
        """
        Read-only view of the protected header bucket.

        The returned mapping (and any nested dicts or lists reached through it) is immutable: direct item
        assignment, deletion or in-place mutation of nested values raises an error. This guarantees that the
        header attributes observed by the application always correspond to the bytes used by the cryptographic
        operations (see :attr:`phdr_encoded`). Use the :attr:`phdr` setter or :func:`phdr_update` for
        controlled modifications; both invalidate the cached encoded protected header.

        :returns: An immutable mapping of the protected header attributes.
        """
        return _FrozenHeaderDict(self._phdr)

    @phdr.setter
    def phdr(self, new_phdr: Mapping) -> None:
        new_phdr = _thaw_header_value(new_phdr)
        if type(new_phdr) is not dict:
            raise TypeError("protected header should be of type 'dict'")
        self._phdr = deepcopy(new_phdr)
        self._phdr_encoded = None

    @property
    def uhdr(self) -> Mapping:
        """
        Read-only view of the unprotected header bucket.

        Like :attr:`phdr`, the returned mapping is immutable; use the :attr:`uhdr` setter or
        :func:`uhdr_update` for controlled modifications.

        :returns: An immutable mapping of the unprotected header attributes.
        """
        return _FrozenHeaderDict(self._uhdr)

    @uhdr.setter
    def uhdr(self, new_uhdr: Mapping) -> None:
        new_uhdr = _thaw_header_value(new_uhdr)
        if type(new_uhdr) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")
        self._uhdr = deepcopy(new_uhdr)

    def phdr_update(self, phdr_params: Mapping) -> None:
        phdr_params = _thaw_header_value(phdr_params)
        if type(phdr_params) is not dict:
            raise TypeError("protected header should be of type 'dict'")
        self._phdr.update(phdr_params)
        self._phdr_encoded = None

    def uhdr_update(self, uhdr_params: Mapping) -> None:
        uhdr_params = _thaw_header_value(uhdr_params)
        if type(uhdr_params) is not dict:
            raise TypeError("unprotected header should be of type 'dict'")
        self._uhdr.update(uhdr_params)

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

        For decoded messages that were never modified through the :attr:`phdr` setter or :func:`phdr_update`,
        the original encoded bytes are preserved and returned as-is. After a controlled modification the
        protected header is re-encoded from the current header attributes, so the bytes used by the
        cryptographic operations always match the attributes visible through :attr:`phdr`.

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
        return self._uhdr

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
