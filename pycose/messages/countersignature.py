from typing import Optional, Union, TYPE_CHECKING

import cbor2

from pycose import headers, utils
from pycose.exceptions import CoseException
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.messages.sign1message import Sign1Message
from pycose.messages.signcommon import SignCommon
from pycose.messages.signer import CoseSignature
from pycose.messages.signmessage import _SignMessage

if TYPE_CHECKING:
    from pycose.keys.ec2 import EC2
    from pycose.keys.okp import OKP
    from pycose.keys.rsa import RSA

CBOR = bytes


def create_countersign_structure(context: str,
                                 target: 'CountersignedObject',
                                 detached_payload: Optional[bytes] = None) -> CBOR:
    if target is None:
        raise CoseException("Cannot create a countersignature structure without a countersigned object")

    other_fields = []

    if isinstance(target, CoseSignature):
        body = target._parent
        if body is None:
            raise CoseException("Cannot countersign a COSE_Signature without its parent COSE_Sign message")

        structure = [context, body.phdr_encoded, target.phdr_encoded, target.external_aad]
        payload = body.payload
        other_fields.append(target.signature)
    elif isinstance(target, Sign1Message):
        structure = [context, target.phdr_encoded, target.external_aad]
        payload = target.payload
        other_fields.append(target.signature)
    elif isinstance(target, _SignMessage):
        structure = [context, target.phdr_encoded, target.external_aad]
        payload = target.payload
        other_fields.append([signer.signature for signer in target.signers])
    else:
        structure = [context, target.phdr_encoded, target.external_aad]
        payload = target.payload

    if detached_payload is not None:
        if payload is not None:
            raise CoseException("Detached payload must be None when payload is set")
        payload = detached_payload

    if payload is None:
        raise CoseException("Missing payload and no detached payload provided")

    structure.append(payload)
    structure.append(other_fields)
    return cbor2.dumps(structure)


class CountersignatureV2(SignCommon):
    context = "CounterSignatureV2"
    cbor_tag = None

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool = True) -> 'CountersignatureV2':
        msg = super(CountersignatureV2, cls).from_cose_obj(cose_obj, allow_unknown_attributes)
        msg._parent = None
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 signature: bytes = b'',
                 key: Optional[Union['EC2', 'OKP', 'RSA']] = None,
                 *args,
                 **kwargs):
        super().__init__(phdr=phdr, uhdr=uhdr, payload=signature, external_aad=b'', key=key, *args, **kwargs)
        self._parent = None

    @property
    def signature(self) -> bytes:
        return self._payload

    @signature.setter
    def signature(self, value: bytes) -> None:
        if not isinstance(value, bytes):
            raise TypeError("Signature must be of type 'bytes'")
        self._payload = value

    def _create_sig_structure(self, detached_payload: Optional[bytes] = None) -> CBOR:
        return create_countersign_structure(self.context, self._parent, detached_payload)

    def encode(self, sign: bool = False, detached_payload: Optional[bytes] = None, *args, **kwargs) -> list:
        if sign:
            self.signature = self.compute_signature(detached_payload)
        return [self.phdr_encoded, self.uhdr_encoded, self.signature]

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()
        return f'<COSE_CountersignatureV2: [{phdr}, {uhdr}, {utils.truncate(self.signature)}]>'


class CounterSignature0V2(Sign1Message):
    context = "CounterSignature0V2"
    cbor_tag = None

    @property
    def _parent(self):
        return self._countersigned_object

    @_parent.setter
    def _parent(self, value) -> None:
        self._countersigned_object = value

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool = True) -> 'CounterSignature0V2Message':
        msg = super(CounterSignature0V2, cls).from_cose_obj(cose_obj, allow_unknown_attributes)
        msg._countersigned_object = None
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 signature: bytes = b'',
                 key: Optional[Union['EC2', 'OKP', 'RSA']] = None,
                 *args,
                 **kwargs):
        super().__init__(phdr=phdr,
                         uhdr=uhdr,
                         payload=b'',
                         external_aad=b'',
                         key=key,
                         *args,
                         **kwargs)
        self._countersigned_object = None
        self.signature = signature

    def _create_sig_structure(self, detached_payload: Optional[bytes] = None) -> CBOR:
        return create_countersign_structure(self.context, self._countersigned_object, detached_payload)

    def encode(self, tag: bool = False, sign: bool = False, detached_payload: Optional[bytes] = None,
               *args, **kwargs) -> CBOR:
        if sign:
            self.signature = self.compute_signature(detached_payload)
        return cbor2.dumps([self.phdr_encoded, self.uhdr_encoded, b'', self.signature],
                           default=self._custom_cbor_encoder)

    def compute_signature(self, detached_payload: Optional[bytes] = None, *args, **kwargs) -> bytes:
        alg = self.get_attr(headers.Algorithm)
        self._key_verification(alg, SignOp)
        return alg.sign(key=self.key, data=self._create_sig_structure(detached_payload))

    def verify_signature(self, detached_payload: Optional[bytes] = None, *args, **kwargs) -> bool:
        alg = self.get_attr(headers.Algorithm)
        self._key_verification(alg, VerifyOp)
        return alg.verify(key=self.key,
                          data=self._create_sig_structure(detached_payload),
                          signature=self.signature)

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()
        return f'<COSE_CounterSignature0V2: [{phdr}, {uhdr}, {utils.truncate(self.signature)}]>'


CounterSignature0V2Message = CounterSignature0V2
Countersignature0V2 = CounterSignature0V2
CounterSignatureV2Message = CountersignatureV2
CountersignedObject = Union[SignCommon, _SignMessage]
