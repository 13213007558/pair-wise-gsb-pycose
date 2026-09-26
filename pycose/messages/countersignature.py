"""
RFC 9338 - CBOR Object Signing and Encryption (COSE): Countersignatures

COSE_Countersignature = [
   protected: empty_or_serialized_map,
   unprotected: unprotected_header_map,
   signature: bstr
]

Countersign_structure = [
   context: "CounterSignatureV2" / "CounterSignature0V2",
   body_protected: empty_or_serialized_map,
   ? sign_protected: empty_or_serialized_map,
   external_aad: bstr,
   payload: bstr,
   other_fields: [
       ? signature: bstr,
       ? signatures: [+ bstr]
   ]
]
"""

from typing import Optional, TYPE_CHECKING, Union

import cbor2

from pycose import headers, utils
from pycose.exceptions import CoseException
from pycose.messages.sign1message import Sign1Message
from pycose.messages.signcommon import SignCommon
from pycose.messages.signer import CoseSignature
from pycose.messages.signmessage import _SignMessage

if TYPE_CHECKING:
    from pycose.keys.ec2 import EC2
    from pycose.keys.okp import OKP
    from pycose.keys.rsa import RSA
    from pycose.messages.cosemessage import CoseMessage

CBOR = bytes


def create_countersign_structure(context: str,
                                 target: 'CoseMessage',
                                 detached_payload: Optional[bytes] = None) -> CBOR:
    """
    Create the Countersign_structure (RFC 9338, Section 3) for a countersigned object.

    The structure is built from the individual fields of the countersigned object, not from a
    re-encoding of the complete message:

    - body_protected: the (raw) protected header bucket of the countersigned message.
    - sign_protected: only present when countersigning a COSE_Signature (a signer of a COSE_Sign
      message); carries the protected header bucket of that COSE_Signature.
    - external_aad: the external additional authenticated data of the countersigned message.
    - payload: the payload (or ciphertext) of the countersigned message.
    - other_fields: for a COSE_Sign1 the value of its signature field, for a COSE_Sign the array of
      the signature values of its COSE_Signature structures; empty in all other cases.

    :param context: The context string, "CounterSignatureV2" or "CounterSignature0V2".
    :param target: The COSE object that is countersigned.
    :param detached_payload: Optional detached payload of the countersigned message.
    :return: The CBOR-encoded Countersign_structure.
    """

    if target is None:
        raise CoseException("Cannot create a Countersign_structure without a countersigned object")

    other_fields = []

    if isinstance(target, CoseSignature):
        # countersignature on a single signer of a COSE_Sign message
        body = target._parent
        if body is None:
            raise CoseException("Cannot countersign a COSE_Signature that is not part of a COSE_Sign message")
        structure = [context, body.phdr_encoded, target.phdr_encoded]
        external_aad = body.external_aad
        payload = body.payload
    else:
        structure = [context, target.phdr_encoded]
        external_aad = target.external_aad
        payload = target.payload

        if isinstance(target, Sign1Message):
            other_fields = [target.signature]
        elif isinstance(target, _SignMessage):
            other_fields = [[s.signature for s in target.signers]]

    if detached_payload is not None:
        if payload is not None:
            raise CoseException("Detached payload must be None when payload is set")
        payload = detached_payload

    if payload is None:
        raise CoseException("Missing payload and no detached payload provided")

    structure.append(external_aad)
    structure.append(payload)
    structure.append(other_fields)

    return cbor2.dumps(structure)


class Countersignature(SignCommon):
    """ A COSE_Countersignature structure (RFC 9338), carried by the CounterSignatureV2 header. """

    context = "CounterSignatureV2"
    cbor_tag = None

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool = True) -> 'Countersignature':
        """ Parses a COSE_Countersignature structure. """

        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg._parent = None
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 signature: bytes = b'',
                 external_aad: Optional[bytes] = b'',
                 key: Optional[Union['EC2', 'OKP', 'RSA']] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr, uhdr, payload=signature, external_aad=external_aad, key=key, *args, **kwargs)

        self._parent = None

    @property
    def signature(self) -> bytes:
        return self._payload

    @signature.setter
    def signature(self, value: bytes):
        if not isinstance(value, bytes):
            raise TypeError("Signature must be of type 'bytes'")

        self._payload = value

    def _create_sig_structure(self, detached_payload: Optional[bytes] = None) -> CBOR:
        return create_countersign_structure(self.context, self._parent, detached_payload)

    def encode(self, sign: bool = False, detached_payload: Optional[bytes] = None, *args, **kwargs) -> list:
        """
        Encodes the COSE_Countersignature structure.

        :param sign: When True, (re)computes the signature over the countersigned object.
        :param detached_payload: Optional detached payload of the countersigned object.
        """

        if sign:
            self.signature = self.compute_signature(detached_payload)

        return [self.phdr_encoded, self.uhdr_encoded, self.signature]

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Countersignature: [{phdr}, {uhdr}, {utils.truncate(self._payload)}]>'


class Countersignature0(SignCommon):
    """ A CounterSignature0V2 signature (RFC 9338): a bare signature without its own headers. """

    context = "CounterSignature0V2"
    cbor_tag = None

    def __init__(self,
                 signature: bytes = b'',
                 key: Optional[Union['EC2', 'OKP', 'RSA']] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr={}, uhdr={}, payload=signature, external_aad=b'', key=key, *args, **kwargs)

        self._parent = None

    @property
    def signature(self) -> bytes:
        return self._payload

    @signature.setter
    def signature(self, value: bytes):
        if not isinstance(value, bytes):
            raise TypeError("Signature must be of type 'bytes'")

        self._payload = value

    def _create_sig_structure(self, detached_payload: Optional[bytes] = None) -> CBOR:
        return create_countersign_structure(self.context, self._parent, detached_payload)

    def _get_alg(self):
        alg = self.get_attr(headers.Algorithm)

        if alg is None:
            if self.key is None:
                raise CoseException("Key cannot be None")
            alg = self.key.alg

        if alg is None:
            raise CoseException("No algorithm found: a CounterSignature0V2 signature requires an "
                                "algorithm in the COSE key")

        return alg

    def compute_signature(self, detached_payload: Optional[bytes] = None, *args, **kwargs) -> bytes:
        from pycose.keys.keyops import SignOp

        alg = self._get_alg()

        self._key_verification(alg, SignOp)

        return alg.sign(key=self.key, data=self._create_sig_structure(detached_payload))

    def verify_signature(self, detached_payload: Optional[bytes] = None, *args, **kwargs) -> bool:
        from pycose.keys.keyops import VerifyOp

        alg = self._get_alg()

        self._key_verification(alg, VerifyOp)

        return alg.verify(key=self.key, data=self._create_sig_structure(detached_payload), signature=self.signature)

    def encode(self, *args, **kwargs) -> bytes:
        """ A CounterSignature0V2 signature is encoded as a bare byte string. """

        return self.signature

    def __repr__(self) -> str:
        return f'<COSE_Countersignature0: [{utils.truncate(self._payload)}]>'
