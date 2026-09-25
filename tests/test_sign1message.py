import hashlib
import io

import cbor2
import pytest

from cryptography.hazmat.primitives.asymmetric import utils

from pycose.exceptions import CoseException, CoseIllegalAlgorithm, CoseIllegalKeyOps
from pycose.keys import EC2Key, OKPKey, RSAKey
from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.messages.sign1message import Sign1Message


class ChunkedStream:
    def __init__(self, payload: bytes, chunk_size: int):
        self.payload = payload
        self.chunk_size = chunk_size
        self.offset = 0
        self.max_chunk = 0

    def read(self, size=-1):
        if size is None or size < 0:
            size = len(self.payload) - self.offset

        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        self.max_chunk = max(self.max_chunk, len(chunk))
        return chunk


class ShortReadStream(ChunkedStream):
    def read(self, size=-1):
        return super().read(min(size, max(1, size // 2)))


class FailingStream:
    def read(self, size=-1):
        raise OSError("stream read failed")


class NonBytesStream:
    def read(self, size=-1):
        return "not bytes"


class OversizedReadStream:
    def __init__(self, payload: bytes):
        self.payload = payload

    def read(self, size=-1):
        return self.payload[:size + 1]


@pytest.mark.parametrize('curve,alg', [
    ('P_256', 'ES256'),
    ('P_384', 'ES384'),
    ('P_521', 'ES512'),
])
@pytest.mark.parametrize('chunk_size', [1, 2, 3, 7, 4096])
def test_streaming_detached_ecdsa_cross_verifies(curve, alg, chunk_size):
    key = EC2Key.generate_key(crv=curve, optional_params={'ALG': alg})
    payload = b'\x00the streaming payload\xff' * 31

    signer = Sign1Message(phdr={'ALG': alg}, external_aad=b'external aad', key=key)
    stream = ChunkedStream(payload, chunk_size)
    encoded_stream = signer.encode_stream(stream, len(payload), chunk_size)
    assert stream.max_chunk <= chunk_size

    decoded_stream = Sign1Message.decode(encoded_stream)
    decoded_stream.external_aad = b'external aad'
    decoded_stream.key = key

    assert len(decoded_stream.signature) == 2 * key.crv.size
    assert decoded_stream.verify_signature(detached_payload=payload)

    encoded_regular = Sign1Message(
        phdr={'ALG': alg},
        external_aad=b'external aad',
        key=key
    ).encode(detached_payload=payload)
    decoded_regular = Sign1Message.decode(encoded_regular)
    decoded_regular.external_aad = b'external aad'
    decoded_regular.key = key

    assert decoded_regular.verify_signature_stream(
        ChunkedStream(payload, chunk_size), len(payload), chunk_size
    )


def test_streaming_handles_streams_that_return_short_reads():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    payload = b'short reads are allowed' * 17

    encoded = Sign1Message(phdr={'ALG': 'ES256'}, key=key).encode_stream(
        ShortReadStream(payload, 32), len(payload), 32
    )
    decoded = Sign1Message.decode(encoded)
    decoded.key = key

    assert decoded.verify_signature(detached_payload=payload)


@pytest.mark.parametrize('payload_length', [0, 23, 24, 255, 256, 65535, 65536])
def test_streaming_hashes_complete_sig_structure(payload_length):
    payload = bytes(i % 251 for i in range(payload_length))
    msg = Sign1Message(
        phdr={'ALG': 'ES256'},
        uhdr={'KID': b'kid'},
        external_aad=b'external aad'
    )

    streaming_digest = msg._hash_streaming_sig_structure(
        ChunkedStream(payload, 37), payload_length, 37, 'sha256'
    )
    one_shot_digest = hashlib.sha256(msg._create_sig_structure(payload)).digest()

    assert streaming_digest == one_shot_digest


@pytest.mark.parametrize('chunk_size', [1, 17, 64])
def test_streaming_read_buffer_scales_with_chunk_size(chunk_size):
    payload = bytes(range(256)) * 4
    msg = Sign1Message(phdr={'ALG': 'ES256'})
    stream = ChunkedStream(payload, chunk_size)

    msg._hash_streaming_sig_structure(stream, len(payload), chunk_size, 'sha256')

    assert stream.max_chunk == chunk_size


def test_streaming_detached_rsa_pss_cross_verifies():
    key = RSAKey.generate_key(2048, optional_params={'ALG': 'PS256'})
    payload = b'large detached payload' * 23

    encoded = Sign1Message(phdr={'ALG': 'PS256'}, external_aad=b'aad', key=key).encode_stream(
        io.BytesIO(payload), len(payload), 17
    )
    decoded = Sign1Message.decode(encoded)
    decoded.external_aad = b'aad'
    decoded.key = key

    assert decoded.verify_signature(detached_payload=payload)

    encoded = Sign1Message(phdr={'ALG': 'PS256'}, external_aad=b'aad', key=key).encode(
        detached_payload=payload
    )
    decoded = Sign1Message.decode(encoded)
    decoded.external_aad = b'aad'
    decoded.key = key

    assert decoded.verify_signature_stream(io.BytesIO(payload), len(payload), 17)


def test_streaming_verification_includes_external_aad():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    payload = b'payload with external aad'

    encoded = Sign1Message(
        phdr={'ALG': 'ES256'},
        external_aad=b'expected aad',
        key=key
    ).encode_stream(io.BytesIO(payload), len(payload), 5)

    decoded = Sign1Message.decode(encoded)
    decoded.key = key
    decoded.external_aad = b'unexpected aad'

    assert not decoded.verify_signature_stream(io.BytesIO(payload), len(payload), 5)


def test_streaming_verification_rejects_malformed_ecdsa_signature():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    msg = Sign1Message(phdr={'ALG': 'ES256'}, key=key)
    msg.signature = b'not a raw signature'

    assert not msg.verify_signature_stream(io.BytesIO(b'payload'), 7)


@pytest.mark.parametrize('curve,alg,signature_length', [
    ('P_256', 'ES256', 64),
    ('P_384', 'ES384', 96),
    ('P_521', 'ES512', 132),
])
def test_streaming_ecdsa_signature_uses_cose_raw_encoding(curve, alg, signature_length):
    key = EC2Key.generate_key(crv=curve, optional_params={'ALG': alg})
    payload = b'ecdsa encoding'
    signer = Sign1Message(phdr={'ALG': alg}, key=key)

    signature = signer.compute_signature_stream(io.BytesIO(payload), len(payload), 4)

    assert len(signature) == signature_length
    coordinate_length = signature_length // 2
    r_value, s_value = utils.decode_dss_signature(
        utils.encode_dss_signature(
            int.from_bytes(signature[:coordinate_length], 'big'),
            int.from_bytes(signature[coordinate_length:], 'big')
        )
    )
    assert r_value == int.from_bytes(signature[:coordinate_length], 'big')
    assert s_value == int.from_bytes(signature[coordinate_length:], 'big')


@pytest.mark.parametrize('alg,key', [
    ('EdDSA', lambda: OKPKey.generate_key(crv='ED25519', optional_params={'ALG': 'EdDSA'})),
    ('RS256', lambda: RSAKey.generate_key(2048, optional_params={'ALG': 'RS256'})),
])
def test_streaming_rejects_unsupported_algorithms(alg, key):
    key = key()
    msg = Sign1Message(phdr={'ALG': alg}, key=key)

    with pytest.raises(CoseIllegalAlgorithm, match="RSA-PSS and ECDSA"):
        msg.compute_signature_stream(io.BytesIO(b'payload'), 7)

    with pytest.raises(CoseIllegalAlgorithm, match="RSA-PSS and ECDSA"):
        msg.verify_signature_stream(io.BytesIO(b'payload'), 7)


@pytest.mark.parametrize('declared_length,payload', [
    (6, b'payload'),
    (8, b'payload'),
])
def test_streaming_rejects_declared_length_mismatch(declared_length, payload):
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    msg = Sign1Message(phdr={'ALG': 'ES256'}, key=key)

    with pytest.raises(CoseException, match="declared payload length|more bytes"):
        msg.compute_signature_stream(io.BytesIO(payload), declared_length)


def test_streaming_does_not_return_signature_after_read_failure():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    msg = Sign1Message(phdr={'ALG': 'ES256'}, key=key)

    with pytest.raises(CoseException, match="Failed to read payload stream"):
        msg.compute_signature_stream(FailingStream(), 7)

    assert msg.signature == b''

    encoded = Sign1Message(phdr={'ALG': 'ES256'}, key=key).encode(detached_payload=b'payload')
    decoded = Sign1Message.decode(encoded)
    decoded.key = key

    with pytest.raises(CoseException, match="Failed to read payload stream"):
        decoded.verify_signature_stream(FailingStream(), 7)


def test_streaming_rejects_non_bytes_stream_output():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    msg = Sign1Message(phdr={'ALG': 'ES256'}, key=key)

    with pytest.raises(TypeError, match="Payload stream must return bytes"):
        msg.compute_signature_stream(NonBytesStream(), 7)


def test_streaming_rejects_oversized_read():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    msg = Sign1Message(phdr={'ALG': 'ES256'}, key=key)

    with pytest.raises(CoseException, match="more bytes than requested"):
        msg.compute_signature_stream(OversizedReadStream(b'payload'), 7, 4)


def test_streaming_rejects_object_without_read_method():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    msg = Sign1Message(phdr={'ALG': 'ES256'}, key=key)

    with pytest.raises(TypeError, match="Payload stream must provide a read"):
        msg.compute_signature_stream(object(), 7)


def test_streaming_requires_detached_payload():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=b'attached', key=key)

    with pytest.raises(CoseException, match="Detached payload"):
        msg.compute_signature_stream(io.BytesIO(b'attached'), 8)


def test_streaming_rejects_invalid_chunk_size():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    msg = Sign1Message(phdr={'ALG': 'ES256'}, key=key)

    with pytest.raises(ValueError, match="Chunk size"):
        msg.compute_signature_stream(io.BytesIO(b'payload'), 7, 0)


def test_streaming_empty_payload_uses_correct_structure():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    signer = Sign1Message(phdr={'ALG': 'ES256'}, key=key)

    signature = signer.compute_signature_stream(io.BytesIO(b''), 0)
    encoded = signer.encode(detached_payload=b'')

    decoded = Sign1Message.decode(encoded)
    decoded.key = key
    assert decoded.verify_signature_stream(io.BytesIO(b''), 0)
    assert decoded.verify_signature_stream(io.BytesIO(b''), 0) == decoded.verify_signature(detached_payload=b'')
    assert len(signature) == 64


def test_sign1_encoding(test_sign1):
    test_input = test_sign1['input']
    test_output = test_sign1['output']

    msg = Sign1Message(
        phdr=test_input['protected'],
        uhdr=test_input['unprotected'],
        payload=test_input['plaintext'],
        external_aad=test_input['external_aad'])

    assert msg.phdr_encoded == test_output['protected']
    assert msg.uhdr_encoded == test_output['unprotected']

    assert msg._create_sig_structure() == test_output['structure']

    key = CoseKey.from_dict(test_sign1["cek"])
    key.key_ops = [SignOp, VerifyOp]
    msg.key = key

    assert msg.compute_signature() == test_output['signature']
    assert cbor2.loads(msg.encode(tag=test_sign1['cbor_tag'])) == test_output['result']


def test_sign1_decoding(test_sign1):
    if not test_sign1['cbor_tag']:
        pytest.skip("Missing CBOR tag")

    test_input = test_sign1['input']
    test_output = test_sign1['output']

    msg = Sign1Message.decode(cbor2.dumps(test_output['result']))
    msg.external_aad = test_input['external_aad']

    key = CoseKey.from_dict(test_sign1["cek"])
    key.key_ops = [VerifyOp]
    msg.key = key

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    assert msg.verify_signature()


def test_detached_payload():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    msg = Sign1Message(phdr={'ALG': 'ES256'})
    msg.key = ec2_key

    encoded = msg.encode(detached_payload=payload)

    msg = Sign1Message.decode(encoded)
    msg.key = ec2_key

    assert msg.payload is None

    assert msg.verify_signature(detached_payload=payload)


def test_attach_payload():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    # Sign with detached payload
    msg = Sign1Message(phdr={'ALG': 'ES256'})
    msg.key = ec2_key
    encoded = msg.encode(detached_payload=payload)

    # Decode, attach payload, and re-encode
    msg = Sign1Message.decode(encoded)
    msg.payload = payload
    sig = msg.signature
    encoded = msg.encode(sign=False)

    # Decode and verify
    msg = Sign1Message.decode(encoded)
    msg.key = ec2_key
    assert msg.verify_signature()

    # Make sure re-encoding didn't change the signature
    assert msg.signature == sig


def test_detach_payload():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    # Sign with attached payload
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=payload)
    msg.key = ec2_key
    encoded = msg.encode()

    # Decode, detach payload, and re-encode
    msg = Sign1Message.decode(encoded)
    msg.payload = None
    sig = msg.signature
    encoded = msg.encode(sign=False)

    # Decode and verify
    msg = Sign1Message.decode(encoded)
    msg.key = ec2_key
    assert msg.verify_signature(detached_payload=payload)

    # Make sure re-encoding didn't change the signature
    assert msg.signature == sig


def test_fail_on_missing_payload_signing():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    msg = Sign1Message(phdr={'ALG': 'ES256'})
    msg.key = ec2_key

    with pytest.raises(CoseException, match="Missing payload"):
        msg.encode()


def test_fail_on_missing_payload_verification():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    msg = Sign1Message(phdr={'ALG': 'ES256'})
    msg.key = ec2_key
    encoded = msg.encode(detached_payload=payload)

    msg = Sign1Message.decode(encoded)
    msg.key = ec2_key

    with pytest.raises(CoseException, match="Missing payload"):
        msg.verify_signature()


@pytest.mark.parametrize('alg', ['ES384', 'ES512'])
def test_fail_on_non_matching_algorithms_phdr(alg):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload="signed message".encode('utf-8'))

    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': alg})
    msg.key = ec2_key

    with pytest.raises(CoseIllegalAlgorithm) as excinfo:
        msg.encode()

    assert "Conflicting algorithms" in str(excinfo.value)


@pytest.mark.parametrize('ops',
                         ['VERIFY', 'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP',
                          'DERIVE_KEY', 'DERIVE_BITS', 'MAC_CREATE', 'MAC_VERIFY'])
def test_fail_on_illegal_keyops_signing(ops):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload="signed message".encode('utf-8'))

    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'KEY_OPS': [ops]})
    msg.key = ec2_key

    with pytest.raises(CoseIllegalKeyOps) as excinfo:
        msg.encode()

    assert "Illegal key operations specified." in str(excinfo.value)


@pytest.mark.parametrize('ops',
                         ['SIGN', 'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP',
                          'DERIVE_KEY', 'DERIVE_BITS', 'MAC_CREATE', 'MAC_VERIFY'])
def test_fail_on_illegal_keyops_verifying(ops):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload="signed message".encode('utf-8'))

    ec2_key = EC2Key.generate_key(crv='P_256')
    msg.key = ec2_key

    msg = msg.encode()

    msg = Sign1Message.decode(msg)
    # set an illegal key op
    if ops in {'ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP', 'MAC_CREATE', 'MAC_VERIFY'}:
        with pytest.raises(CoseIllegalKeyOps) as excinfo:
            ec2_key.key_ops = [ops]

        assert "Invalid COSE key operation" in str(excinfo.value)
        return
    else:
        ec2_key.key_ops = [ops]

    msg.key = ec2_key

    with pytest.raises(CoseIllegalKeyOps) as excinfo:
        msg.verify_signature()

    assert "Illegal key operations specified." in str(excinfo.value)
