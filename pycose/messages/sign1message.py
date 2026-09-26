from typing import BinaryIO, Iterable, Optional, Union, TYPE_CHECKING

import cbor2

from pycose import utils
from pycose import headers
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.messages.cosemessage import CoseMessage
from pycose.messages.signcommon import SignCommon
from pycose.exceptions import CoseException

if TYPE_CHECKING:
    from pycose.keys.ec2 import EC2
    from pycose.keys.okp import OKP
    from pycose.keys.rsa import RSA

CBOR = bytes

#: Default chunk size (in bytes) used when reading a detached payload stream
STREAM_CHUNK_SIZE = 64 * 1024


def _encode_bstr_header(length: int) -> bytes:
    """ Encodes the CBOR header of a definite-length byte string of the given size. """
    if length < 24:
        return bytes([0x40 + length])
    elif length < 2 ** 8:
        return b'\x58' + length.to_bytes(1, 'big')
    elif length < 2 ** 16:
        return b'\x59' + length.to_bytes(2, 'big')
    elif length < 2 ** 32:
        return b'\x5a' + length.to_bytes(4, 'big')
    else:
        return b'\x5b' + length.to_bytes(8, 'big')


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

    def _hash_sig_structure_stream(self,
                                   payload_stream: Union[BinaryIO, Iterable[bytes]],
                                   payload_length: int,
                                   chunk_size: int) -> bytes:
        """
        Incrementally hashes the full Sig_structure, reading the detached payload from a stream.

        The hashed content is identical to _create_sig_structure: the CBOR array header,
        the context, the protected header bytes, the external AAD and the payload as a
        definite-length byte string.

        :return: the digest of the Sig_structure
        """
        alg = self.get_attr(headers.Algorithm)

        if not getattr(alg, 'allow_prehash', False):
            raise CoseException(f"Algorithm {alg.fullname} does not support the streaming sign/verify interface")

        if self.payload is not None:
            raise CoseException("Payload must be detached (None) when using the streaming interface")

        if not isinstance(payload_length, int) or payload_length < 0:
            raise ValueError("payload_length must be a non-negative integer")

        if chunk_size <= 0:
            raise ValueError("chunk_size must be a positive integer")

        hasher = alg.create_hasher()

        # Sig_structure is a CBOR array of 4 elements: context, body_protected, external_aad, payload
        hasher.update(b'\x84')
        for item in self._base_structure([self.context]):
            hasher.update(cbor2.dumps(item))

        # payload byte string header with the declared length, followed by the streamed content
        hasher.update(_encode_bstr_header(payload_length))

        remaining = payload_length
        if hasattr(payload_stream, 'read'):
            while remaining > 0:
                chunk = payload_stream.read(min(chunk_size, remaining))
                if not chunk:
                    raise CoseException(f"Payload stream ended early: expected {payload_length} bytes, "
                                        f"received {payload_length - remaining}")
                hasher.update(chunk)
                remaining -= len(chunk)
            if payload_stream.read(1):
                raise CoseException(f"Payload stream contains more than the declared {payload_length} bytes")
        else:
            for chunk in payload_stream:
                if len(chunk) > remaining:
                    raise CoseException(f"Payload stream contains more than the declared {payload_length} bytes")
                hasher.update(chunk)
                remaining -= len(chunk)
            if remaining > 0:
                raise CoseException(f"Payload stream ended early: expected {payload_length} bytes, "
                                    f"received {payload_length - remaining}")

        return hasher.digest()

    def compute_signature_stream(self,
                                 payload_stream: Union[BinaryIO, Iterable[bytes]],
                                 payload_length: int,
                                 chunk_size: int = STREAM_CHUNK_SIZE) -> bytes:
        """
        Computes the signature over a COSE message with a detached payload read from a stream.

        The payload must be a one-shot byte stream (a file-like object or an iterable of bytes
        chunks) whose total length is known upfront and passed as payload_length. If the stream
        yields fewer or more bytes than declared, or reading fails, an exception is raised and no
        signature is produced.

        Only algorithms that can safely operate on a pre-hashed message (RSA-PSS and ECDSA) are
        supported by this interface.

        :param payload_stream: the detached payload as a byte stream
        :param payload_length: the total length of the detached payload in bytes
        :param chunk_size: the maximum number of bytes read from the stream at once

        :returns: the signature
        """
        alg = self.get_attr(headers.Algorithm)

        self._key_verification(alg, SignOp)

        digest = self._hash_sig_structure_stream(payload_stream, payload_length, chunk_size)

        return alg.sign_prehashed(self.key, digest)

    def verify_signature_stream(self,
                                payload_stream: Union[BinaryIO, Iterable[bytes]],
                                payload_length: int,
                                chunk_size: int = STREAM_CHUNK_SIZE) -> bool:
        """
        Verifies the signature of a received COSE message with a detached payload read from a stream.

        The payload must be a one-shot byte stream (a file-like object or an iterable of bytes
        chunks) whose total length is known upfront and passed as payload_length. If the stream
        yields fewer or more bytes than declared, or reading fails, an exception is raised.

        Only algorithms that can safely operate on a pre-hashed message (RSA-PSS and ECDSA) are
        supported by this interface.

        :param payload_stream: the detached payload as a byte stream
        :param payload_length: the total length of the detached payload in bytes
        :param chunk_size: the maximum number of bytes read from the stream at once

        :returns: True for a valid signature or False for an invalid signature
        """
        alg = self.get_attr(headers.Algorithm)

        self._key_verification(alg, VerifyOp)

        digest = self._hash_sig_structure_stream(payload_stream, payload_length, chunk_size)

        return alg.verify_prehashed(self.key, digest, self.signature)

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
