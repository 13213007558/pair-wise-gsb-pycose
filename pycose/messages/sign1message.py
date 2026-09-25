from hashlib import new as hash_new
from typing import BinaryIO, Optional, Union, TYPE_CHECKING

import cbor2

from pycose import headers, utils
from pycose.messages.cosemessage import CoseMessage
from pycose.messages.signcommon import SignCommon
from pycose.exceptions import CoseException, CoseIllegalAlgorithm
from pycose.keys.keyops import SignOp, VerifyOp

if TYPE_CHECKING:
    from pycose.algorithms import CoseAlg
    from pycose.keys.ec2 import EC2
    from pycose.keys.okp import OKP
    from pycose.keys.rsa import RSA

CBOR = bytes


def _cbor_byte_string_header(length: int) -> bytes:
    if length < 24:
        return bytes((0x40 | length,))
    if length <= 0xff:
        return bytes((0x58, length))
    if length <= 0xffff:
        return b'\x59' + length.to_bytes(2, 'big')
    if length <= 0xffffffff:
        return b'\x5a' + length.to_bytes(4, 'big')
    if length <= 0xffffffffffffffff:
        return b'\x5b' + length.to_bytes(8, 'big')

    raise CoseException("Payload is too large to encode as a CBOR byte string")


@CoseMessage.record_cbor_tag(18)
class Sign1Message(SignCommon):
    context = "Signature1"
    cbor_tag = 18

    @classmethod
    def from_cose_obj(cls, cose_obj, allow_unknown_attributes: bool) -> 'Sign1Message':
        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)
        msg._signature = cose_obj.pop(0)
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: Optional[bytes] = None,
                 external_aad: bytes = b'',
                 key: Optional[Union['EC2', 'OKP', 'RSA']] = None,
                 *args,
                 **kwargs):

        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

        self._signature = b''

    @property
    def signature(self):
        return self._signature
    
    @signature.setter
    def signature(self, value):
        if not isinstance(value, bytes):
            raise TypeError("Signature must be of type 'bytes'")

        self._signature = value

    def _create_sig_structure(self, detached_payload: Optional[bytes] = None):
        """
        Create the sig_structure that needs to be signed

        :return: to_be_signed
        """
        sig_structure = [self.context]
        sig_structure = self._base_structure(sig_structure)

        if detached_payload is None:
            if self.payload is None:
                raise CoseException("Missing payload and no detached payload provided")
            sig_structure.append(self.payload)
        else:
            if self.payload is not None:
                raise CoseException("Detached payload must be None when payload is set")
            sig_structure.append(detached_payload)

        return cbor2.dumps(sig_structure)

    def _validate_streaming_detached_payload(self, payload_stream: BinaryIO) -> None:
        if self.payload is not None:
            raise CoseException("Detached payload must be None when payload is set")

        if not hasattr(payload_stream, 'read'):
            raise TypeError("Payload stream must provide a read() method")

    def _hash_streaming_sig_structure(self,
                                      payload_stream: BinaryIO,
                                      payload_length: int,
                                      chunk_size: int,
                                      digest_name: str) -> bytes:
        self._validate_streaming_detached_payload(payload_stream)

        if type(payload_length) is not int or payload_length < 0:
            raise ValueError("Payload length must be a non-negative integer")

        if type(chunk_size) is not int or chunk_size <= 0:
            raise ValueError("Chunk size must be a positive integer")

        prefix = b'\x84' + cbor2.dumps(self.context) + cbor2.dumps(self.phdr_encoded) + \
                 cbor2.dumps(self.external_aad)
        hasher = hash_new(digest_name)
        hasher.update(prefix)
        hasher.update(_cbor_byte_string_header(payload_length))

        remaining = payload_length

        try:
            while remaining > 0:
                chunk = payload_stream.read(min(chunk_size, remaining))

                if type(chunk) is not bytes:
                    raise TypeError("Payload stream must return bytes")

                if not chunk:
                    raise CoseException("Payload stream ended before the declared payload length")

                if len(chunk) > remaining:
                    raise CoseException("Payload stream returned more bytes than requested")

                hasher.update(chunk)
                remaining -= len(chunk)

            extra = payload_stream.read(1)
            if type(extra) is not bytes:
                raise TypeError("Payload stream must return bytes")
            if extra:
                raise CoseException("Payload stream contained more bytes than the declared payload length")
        except (CoseException, TypeError, ValueError):
            raise
        except Exception as exception:
            raise CoseException("Failed to read payload stream") from exception

        return hasher.digest()

    def _get_streaming_algorithm(self) -> 'CoseAlg':
        alg = self.get_attr(headers.Algorithm)

        if alg is None or not getattr(alg, 'supports_streaming_prehash', False):
            raise CoseIllegalAlgorithm("Streaming detached Sign1 supports RSA-PSS and ECDSA algorithms")

        return alg

    def compute_signature_stream(self,
                                 payload_stream: BinaryIO,
                                 payload_length: int,
                                 chunk_size: int = 65536) -> bytes:
        """ Compute a signature over a detached payload without buffering it. """

        alg = self._get_streaming_algorithm()
        self._key_verification(alg, SignOp)
        digest = self._hash_streaming_sig_structure(
            payload_stream, payload_length, chunk_size, alg.get_hash_name()
        )

        return alg.sign_digest(key=self.key, digest=digest)

    def verify_signature_stream(self,
                                payload_stream: BinaryIO,
                                payload_length: int,
                                chunk_size: int = 65536) -> bool:
        """ Verify a signature over a detached payload without buffering it. """

        alg = self._get_streaming_algorithm()
        self._key_verification(alg, VerifyOp)
        digest = self._hash_streaming_sig_structure(
            payload_stream, payload_length, chunk_size, alg.get_hash_name()
        )

        return alg.verify_digest(key=self.key, digest=digest, signature=self.signature)

    def encode_stream(self,
                      payload_stream: BinaryIO,
                      payload_length: int,
                      chunk_size: int = 65536,
                      tag: bool = True) -> CBOR:
        """ Encode a detached COSE_Sign1 message from a payload stream. """

        signature = self.compute_signature_stream(payload_stream, payload_length, chunk_size)
        message = [self.phdr_encoded, self.uhdr_encoded, None, signature]

        if tag:
            return cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._custom_cbor_encoder)

        return cbor2.dumps(message, default=self._custom_cbor_encoder)

    def encode(self, tag: bool = True, sign: bool = True, detached_payload: Optional[bytes] = None, *args, **kwargs) -> CBOR:
        """ Encodes the message into a CBOR array with or without a CBOR tag. """

        if sign:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload, self.compute_signature(detached_payload)]
        elif self.signature:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload, self.signature]
        else:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload]

        if tag:
            res = cbor2.dumps(cbor2.CBORTag(self.cbor_tag, message), default=self._custom_cbor_encoder)
        else:
            res = cbor2.dumps(message, default=self._custom_cbor_encoder)

        return res

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()

        return f'<COSE_Sign1: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, ' \
               f'{utils.truncate(self._signature)}]>'
