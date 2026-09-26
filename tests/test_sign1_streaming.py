import io
import os
import tracemalloc

import pytest

from pycose.exceptions import CoseException
from pycose.keys import EC2Key, OKPKey, RSAKey
from pycose.messages.sign1message import Sign1Message

EC_ALGS = [('ES256', 'P_256'), ('ES384', 'P_384'), ('ES512', 'P_521')]
RSA_ALGS = ['PS256', 'PS384', 'PS512']


def chunks(data, sizes):
    """Splits data into chunks cycling through the given sizes."""
    pos = 0
    idx = 0
    while pos < len(data):
        size = sizes[idx % len(sizes)]
        yield data[pos:pos + size]
        pos += size
        idx += 1


@pytest.fixture(scope='module', params=EC_ALGS)
def ec_key(request):
    alg, crv = request.param
    return alg, EC2Key.generate_key(crv=crv)


@pytest.fixture(scope='module', params=RSA_ALGS)
def rsa_key(request):
    alg = request.param
    return alg, RSAKey.generate_key(2048)


@pytest.fixture(scope='module', params=EC_ALGS + [('PS256', None), ('PS384', None), ('PS512', None)])
def signing_key(request):
    alg, crv = request.param
    if crv is None:
        return alg, RSAKey.generate_key(2048)
    return alg, EC2Key.generate_key(crv=crv)


def sign_stream(alg, key, payload, chunk_size, external_aad=b''):
    msg = Sign1Message(phdr={'ALG': alg}, external_aad=external_aad)
    msg.key = key
    return msg.compute_signature_stream(io.BytesIO(payload), len(payload), chunk_size=chunk_size)


def verify_stream(alg, key, signature, payload, chunk_size, external_aad=b''):
    msg = Sign1Message(phdr={'ALG': alg}, external_aad=external_aad)
    msg.key = key
    msg.signature = signature
    return msg.verify_signature_stream(io.BytesIO(payload), len(payload), chunk_size=chunk_size)


@pytest.mark.parametrize('chunk_size', [1, 7, 1024, 65536])
def test_stream_sign_cross_verify_non_stream(signing_key, chunk_size):
    """Streaming signatures must verify with the classic non-streaming entry point."""
    alg, key = signing_key
    payload = os.urandom(100_000)
    aad = b'external aad'

    signature = sign_stream(alg, key, payload, chunk_size, external_aad=aad)

    msg = Sign1Message(phdr={'ALG': alg}, external_aad=aad)
    msg.key = key
    msg.signature = signature
    assert msg.verify_signature(detached_payload=payload)


def test_non_stream_sign_cross_verify_stream(signing_key):
    """Classic non-streaming signatures must verify with the streaming entry point."""
    alg, key = signing_key
    payload = os.urandom(100_000)
    aad = b'external aad'

    msg = Sign1Message(phdr={'ALG': alg}, external_aad=aad)
    msg.key = key
    signature = msg.compute_signature(detached_payload=payload)

    assert verify_stream(alg, key, signature, payload, 4096, external_aad=aad)


def test_stream_sign_arbitrary_chunking(signing_key):
    """Any chunking of the payload stream must produce verifiable signatures."""
    alg, key = signing_key
    payload = os.urandom(10_000)

    signature = sign_stream(alg, key, payload, 4096)

    # verify with an iterator of irregular chunks
    msg = Sign1Message(phdr={'ALG': alg})
    msg.key = key
    msg.signature = signature
    assert msg.verify_signature_stream(chunks(payload, [1, 5000, 3, 4096]), len(payload))

    # sign with an iterator of irregular chunks, verify in one go
    msg = Sign1Message(phdr={'ALG': alg})
    msg.key = key
    signature = msg.compute_signature_stream(chunks(payload, [13, 1, 9000]), len(payload))

    msg = Sign1Message(phdr={'ALG': alg})
    msg.key = key
    msg.signature = signature
    assert msg.verify_signature(detached_payload=payload)


def test_stream_empty_payload(signing_key):
    alg, key = signing_key
    payload = b''

    signature = sign_stream(alg, key, payload, 1024)

    msg = Sign1Message(phdr={'ALG': alg})
    msg.key = key
    msg.signature = signature
    assert msg.verify_signature(detached_payload=payload)
    assert msg.verify_signature_stream(io.BytesIO(payload), 0)


def test_stream_ecdsa_signature_raw_encoding(ec_key):
    """ECDSA streaming signatures must use the raw COSE r || s encoding, not DER."""
    alg, key = ec_key
    size = key.crv.size
    payload = os.urandom(1000)

    signature = sign_stream(alg, key, payload, 512)

    assert len(signature) == 2 * size

    # the ecdsa-package based verifier expects the raw encoding
    msg = Sign1Message(phdr={'ALG': alg})
    msg.key = key
    msg.signature = signature
    assert msg.verify_signature(detached_payload=payload)

    # tampering with s must fail verification
    tampered = signature[:-1] + bytes([signature[-1] ^ 0x01])
    msg.signature = tampered
    assert not msg.verify_signature_stream(io.BytesIO(payload), len(payload))


def test_stream_too_short_payload(signing_key):
    alg, key = signing_key
    payload = os.urandom(1000)

    msg = Sign1Message(phdr={'ALG': alg})
    msg.key = key
    with pytest.raises(CoseException, match='ended early'):
        msg.compute_signature_stream(io.BytesIO(payload), len(payload) + 1)

    with pytest.raises(CoseException, match='ended early'):
        msg.compute_signature_stream(iter([payload]), len(payload) + 1)


def test_stream_too_long_payload(signing_key):
    alg, key = signing_key
    payload = os.urandom(1000)

    msg = Sign1Message(phdr={'ALG': alg})
    msg.key = key
    with pytest.raises(CoseException, match='more than the declared'):
        msg.compute_signature_stream(io.BytesIO(payload), len(payload) - 1)

    with pytest.raises(CoseException, match='more than the declared'):
        msg.compute_signature_stream(iter([payload]), len(payload) - 1)


def test_stream_read_failure_returns_no_signature(signing_key):
    alg, key = signing_key
    payload = os.urandom(1000)

    class FailingStream:
        def __init__(self):
            self.calls = 0

        def read(self, n=-1):
            self.calls += 1
            if self.calls > 1:
                raise OSError('read failure')
            return payload[:100]

    msg = Sign1Message(phdr={'ALG': alg})
    msg.key = key
    with pytest.raises(OSError, match='read failure'):
        msg.compute_signature_stream(FailingStream(), len(payload))


@pytest.mark.parametrize('alg', ['ES256', 'PS256'])
def test_stream_rejects_attached_payload(alg):
    if alg == 'ES256':
        key = EC2Key.generate_key(crv='P_256')
    else:
        key = RSAKey.generate_key(2048)

    msg = Sign1Message(phdr={'ALG': alg}, payload=b'attached')
    msg.key = key
    with pytest.raises(CoseException, match='detached'):
        msg.compute_signature_stream(io.BytesIO(b'data'), 4)


def test_stream_rejects_unsupported_algorithms():
    payload = b'some payload'

    # EdDSA cannot use pre-hashing
    okp_key = OKPKey.generate_key(crv='ED25519')
    msg = Sign1Message(phdr={'ALG': 'EdDSA'})
    msg.key = okp_key
    with pytest.raises(CoseException, match='does not support'):
        msg.compute_signature_stream(io.BytesIO(payload), len(payload))

    # RSASSA-PKCS1 v1.5 is not enabled for the streaming interface
    rsa_key = RSAKey.generate_key(2048)
    msg = Sign1Message(phdr={'ALG': 'RS256'})
    msg.key = rsa_key
    with pytest.raises(CoseException, match='does not support'):
        msg.compute_signature_stream(io.BytesIO(payload), len(payload))

    msg = Sign1Message(phdr={'ALG': 'RS256'})
    msg.key = rsa_key
    msg.signature = b'0' * 256
    with pytest.raises(CoseException, match='does not support'):
        msg.verify_signature_stream(io.BytesIO(payload), len(payload))


def test_stream_memory_scales_with_chunk_size():
    """Peak memory must depend on the chunk size, not on the payload size."""
    key = EC2Key.generate_key(crv='P_256')
    payload = os.urandom(1024 * 1024)

    def peak_memory(chunk_size):
        msg = Sign1Message(phdr={'ALG': 'ES256'})
        msg.key = key
        tracemalloc.start()
        msg.compute_signature_stream(io.BytesIO(payload), len(payload), chunk_size=chunk_size)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return peak

    small = peak_memory(4096)
    large = peak_memory(256 * 1024)

    assert small < 128 * 1024
    assert large > small
