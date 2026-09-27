"""
RFC 9338 - CBOR Object Signing and Encryption (COSE): Countersignatures

COSE_Countersignature = [
   protected: empty_or_serialized_map,
   unprotected: labeled_header,
   signature: bstr
]

Countersign_structure = [
   context: "CounterSignatureV2" / "CounterSignature0V2",
   body_protected: empty_or_serialized_map,
   ? sign_protected: empty_or_serialized_map,
   external_aad: bstr,
   payload: bstr,
   other_fields: [ + bstr ]
]
"""

from typing import Optional, TYPE_CHECKING, Union

import cbor2

from pycose import utils
from pycose.exceptions import CoseException
from pycose.messages.signcommon import SignCommon

if TYPE_CHECKING:
    from pycose.keys.ec2 import EC2
    from pycose.keys.okp import OKP
    from pycose.keys.rsa import RSA

CBOR = bytes


class CoseCounterSignatureBase(SignCommon):
    """ Common behavior of the RFC 9338 countersignature structures. """

    # whether the Countersign_structure carries the sign_protected field
    _has_sign_protected = True

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool) -> 'CoseCounterSignatureBase':
        """ Parses a COSE_Countersignature structure. """

        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 signature: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional[Union['EC2', 'OKP', 'RSA']] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr, uhdr, payload=signature, external_aad=external_aad, key=key, *args, **kwargs)

        # the COSE structure this countersignature is applied to (set on decode or on attachment)
        self._parent = None

    @property
    def cbor_tag(self):
        return None

    @property
    def signature(self) -> bytes:
        return self._payload

    @signature.setter
    def signature(self, value: bytes):
        if not isinstance(value, bytes):
            raise TypeError("Signature must be of type 'bytes'")

        self._payload = value

    def _create_sig_structure(self, detached_payload: Optional[bytes] = None) -> CBOR:
        """
        Create the Countersign_structure (RFC 9338, Section 3) to be signed or verified.

        The structure is built from the fields of the COSE object this countersignature is
        attached to (the parent), never from a re-encoding of the whole message.
        """

        if self._parent is None:
            raise CoseException("Cannot create Countersign_structure: countersignature is not attached to a "
                                "COSE message, signer or recipient structure")

        # context, body_protected and external_aad are taken from the parent structure
        countersign_structure = self._parent._base_structure([self.context])

        if self._has_sign_protected:
            countersign_structure.insert(2, self.phdr_encoded)

        if detached_payload is None:
            payload = self._parent._countersign_payload()
            if payload is None:
                raise CoseException("Missing payload and no detached payload provided")
        else:
            if self._parent._countersign_payload() is not None:
                raise CoseException("Detached payload must be None when payload is set")
            payload = detached_payload

        countersign_structure.append(payload)
        countersign_structure.append(self._parent._countersign_other_fields())

        return cbor2.dumps(countersign_structure)

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<{self.__class__.__name__}: [{phdr}, {uhdr}, {utils.truncate(self.signature)}]>'


class CoseCounterSignature(CoseCounterSignatureBase):
    """
    An RFC 9338 CountersignatureV2 structure: [protected, unprotected, signature].

    Carried as value of the CounterSignatureV2 header attribute, either as a single
    structure or as a list of structures.
    """

    context = "CounterSignatureV2"
    _has_sign_protected = True

    def encode(self, sign: bool = True, detached_payload: Optional[bytes] = None, *args, **kwargs) -> list:
        """
        Encodes the COSE_Countersignature structure.

        :param sign: When True and a key is configured, (re)compute the signature over the parent structure.
        :param detached_payload: Detached payload of the parent structure, if any.
        :returns: A CBOR array [protected, unprotected, signature].
        """

        if sign and self.key is not None:
            self.signature = self.compute_signature(detached_payload)

        return [self.phdr_encoded, self.uhdr_encoded, self.signature]


class CoseCounterSignature0(CoseCounterSignatureBase):
    """
    An RFC 9338 Countersignature0V2 structure: a bare signature byte string.

    Carried as value of the CounterSignature0V2 header attribute. The algorithm and key
    have to be supplied by the application since the structure itself cannot transport them.
    """

    context = "CounterSignature0V2"
    _has_sign_protected = False

    def encode(self, sign: bool = True, detached_payload: Optional[bytes] = None, *args, **kwargs) -> CBOR:
        """
        Encodes the Countersignature0V2 structure.

        :param sign: When True and a key is configured, (re)compute the signature over the parent structure.
        :param detached_payload: Detached payload of the parent structure, if any.
        :returns: The signature as a byte string.
        """

        if sign and self.key is not None:
            self.signature = self.compute_signature(detached_payload)

        return self.signature
