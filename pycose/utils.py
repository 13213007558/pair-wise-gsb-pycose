from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, Callable

import cbor2

from pycose.exceptions import CoseException


def _cbor2_supports_mutable_decode() -> bool:
    """Detect whether the installed cbor2 supports the ``immutable`` decode option (cbor2 >= 6.1)."""
    try:
        cbor2.loads(b"\x80", immutable=False)
        return True
    except TypeError:
        return False


_CBOR2_MUTABLE_DECODE = _cbor2_supports_mutable_decode()


def _to_mutable_containers(obj: Any) -> Any:
    """
    Recursively replace immutable containers in a decoded CBOR structure.

    cbor2 6.x can produce tuples and frozendicts instead of lists and dicts: either for the whole
    document (cbor2 6.0/6.1 decode immutably by default) or only inside CBOR tags (cbor2 >= 6.2
    keeps tag values immutable so that tags stay hashable). Map keys are left untouched so the
    resulting dicts stay valid.
    """
    if isinstance(obj, cbor2.CBORTag):
        return cbor2.CBORTag(obj.tag, _to_mutable_containers(obj.value))
    elif isinstance(obj, (list, tuple)):
        return [_to_mutable_containers(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: _to_mutable_containers(v) for k, v in obj.items()}
    elif isinstance(obj, Mapping):
        return {k: _to_mutable_containers(v) for k, v in obj.items()}
    else:
        return obj


def cbor_loads(data: bytes) -> Any:
    """
    Decode CBOR data into mutable containers (lists and dicts).

    pycose consumes decoded message structures destructively (``pop()``) and requires plain dicts
    for the header buckets, while cbor2 6.x may decode arrays and maps to immutable containers
    (tuples and frozendicts). On cbor2 versions supporting it, the ``immutable=False`` decode
    option is used; any remaining immutable containers (e.g. CBOR tag values) are converted
    afterwards. On cbor2 5.x this behaves exactly like ``cbor2.loads``.

    :param data: CBOR-encoded bytes.
    :return: The decoded CBOR object with mutable containers.
    """
    if _CBOR2_MUTABLE_DECODE:
        obj = cbor2.loads(data, immutable=False)
    else:
        obj = cbor2.loads(data)
    return _to_mutable_containers(obj)


class _CoseAttribute(ABC):
    @classmethod
    def default_parser(cls, value):
        return value

    value_parser: Callable = default_parser

    @classmethod
    @abstractmethod
    def get_registered_classes(cls):
        raise NotImplementedError()

    @classmethod
    def register_attribute(cls) -> Callable:
        def decorator(the_class: '_CoseAttribute'):
            cls.get_registered_classes()[the_class.identifier] = the_class
            cls.get_registered_classes()[the_class.fullname.upper()] = the_class
            return the_class

        return decorator

    @classmethod
    def from_id(cls, attribute: Any, allow_unknown_attributes: bool = False) -> Any:
        if isinstance(attribute, int) and attribute in cls.get_registered_classes():
            return cls.get_registered_classes()[attribute]
        elif isinstance(attribute, str) and attribute.upper() in cls.get_registered_classes():
            return cls.get_registered_classes()[attribute.upper()]
        elif isinstance(attribute, list):
            translated_list = [cls.from_id(attr) for attr in attribute]
            return translated_list
        elif hasattr(attribute, 'identifier') and attribute.identifier in cls.get_registered_classes():
            return cls.get_registered_classes()[attribute.identifier]
        else:
            if allow_unknown_attributes:
                return attribute
            else:
                raise CoseException(f"Unknown COSE attribute with value: [{cls.__name__} - {attribute}]")

    @property
    @abstractmethod
    def identifier(self):
        raise NotImplementedError()

    @property
    @abstractmethod
    def fullname(self) -> str:
        raise NotImplementedError()

    def __eq__(self, other: '_CoseAttribute'):
        return self.identifier == other.identifier

    def __ne__(self, other: '_CoseAttribute'):
        return self.identifier != other.identifier

    def __lt__(self, other: '_CoseAttribute'):
        return self.identifier < other.identifier

    def __le__(self, other: '_CoseAttribute'):
        return self.identifier <= other.identifier

    def __gt__(self, other: '_CoseAttribute'):
        return self.identifier > other.identifier

    def __ge__(self, other: '_CoseAttribute'):
        return self.identifier >= other.identifier

    # def __hash__(self):
    #     return hash((self.identifier, self.fullname))

    def __repr__(self):
        return f'<{self.fullname}: {self.identifier}>'


def truncate(payload: bytes) -> str:
    return f'{payload[:5]} ... ({len(payload)} B)'
