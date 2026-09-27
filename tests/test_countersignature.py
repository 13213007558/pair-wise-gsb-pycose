"""
Tests for RFC 9338 (COSE Countersignatures): CounterSignatureV2 and CounterSignature0V2.
"""

import os

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pycose import headers
from pycose.algorithms import EdDSA
from pycose.exceptions import CoseException
from pycose.keys import EC2Key, OKPKey, SymmetricKey
from pycose.messages.cosemessage import CoseMessage
from pycose.messages.countersignature import Countersignature, create_countersign_structure
from pycose.messages.enc0message import Enc0Message
from pycose.messages.encmessage import EncMessage
from pycose.messages.recipient import KeyWrap
from pycose.messages.sign1message import Sign1Message
from pycose.messages.signer import CoseSignature
from pycose.messages.signmessage import SignMessage


@pytest.fixture
def sign_key():
    return EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256', 'KEY_OPS': ['SIGN', 'VERIFY']})


@pytest.fixture
def countersign_key():
    return OKPKey.generate_key(crv='ED25519', optional_params={'ALG': 'EDDSA', 'KEY_OPS': ['SIGN', 'VERIFY']})


@pytest.fixture
def cek():
    return SymmetricKey.generate_key(32, optional_params={'ALG': 'A256GCM', 'KEY_OPS': ['ENCRYPT', 'DECRYPT']})


def _signed_sign1(sign_key, payload=b'hello world'):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=payload)
    msg.key = sign_key
    msg.signature = msg.compute_signature()
    return msg


def _signed_sign(sign_key, payload=b'signed payload'):
    signer = CoseSignature(phdr={'ALG': 'ES256'}, key=sign_key)
    msg = SignMessage(payload=payload, signers=[signer])
    for s in msg.signers:
        s.signature = s.compute_signature()
    return msg


def _encrypted_enc0(cek, payload=b'secret message'):
    msg = Enc0Message(phdr={'ALG': 'A256GCM', 'IV': os.urandom(12)}, payload=payload, key=cek)
    msg.payload = msg.encrypt()
    return msg


def _wrapped_recipient():
    kek = SymmetricKey.generate_key(16, optional_params={'ALG': 'A128KW', 'KEY_OPS': ['WRAP', 'UNWRAP']})
    return KeyWrap(uhdr={'ALG': 'A128KW'}, key=kek)


def _tamper(data: bytes) -> bytes:
    return data[:-1] + bytes([data[-1] ^ 0x01])


# --------------------------------------------------------------------------------------
# Countersign_structure construction (RFC 9338, Section 3)
# --------------------------------------------------------------------------------------

def test_countersign_structure_sign1(sign_key):
    msg = _signed_sign1(sign_key)

    structure = create_countersign_structure("CounterSignatureV2", msg)

    expected = cbor2.dumps([
        "CounterSignatureV2",
        msg.phdr_encoded,
        b'',
        b'hello world',
        [msg.signature],
    ])
    assert structure == expected


def test_countersign_structure_sign_message(sign_key):
    msg = _signed_sign(sign_key)

    structure = create_countersign_structure("CounterSignatureV2", msg)

    expected = cbor2.dumps([
        "CounterSignatureV2",
        msg.phdr_encoded,
        b'',
        b'signed payload',
        [[s.signature for s in msg.signers]],
    ])
    assert structure == expected


def test_countersign_structure_single_signer(sign_key):
    msg = _signed_sign(sign_key)
    signer = msg.signers[0]

    structure = create_countersign_structure("CounterSignatureV2", signer)

    # sign_protected is present and other_fields is empty
    expected = cbor2.dumps([
        "CounterSignatureV2",
        msg.phdr_encoded,
        signer.phdr_encoded,
        b'',
        b'signed payload',
        [],
    ])
    assert structure == expected


def test_countersign_structure_encrypt0(cek):
    msg = _encrypted_enc0(cek)

    structure = create_countersign_structure("CounterSignature0V2", msg)

    expected = cbor2.dumps([
        "CounterSignature0V2",
        msg.phdr_encoded,
        b'',
        msg.payload,
        [],
    ])
    assert structure == expected


def test_countersign_structure_requires_target():
    with pytest.raises(CoseException):
        create_countersign_structure("CounterSignatureV2", None)


# --------------------------------------------------------------------------------------
# COSE_Sign1
# --------------------------------------------------------------------------------------

def test_sign1_countersign_roundtrip(sign_key, countersign_key):
    msg = _signed_sign1(sign_key)
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'}, unprotected={'KID': b'cs-kid'})

    assert headers.CounterSignatureV2 in msg.uhdr

    encoded = msg.encode()
    decoded = CoseMessage.decode(encoded)

    # raw protected header bytes of the received message must be preserved
    assert decoded.phdr_encoded == cbor2.loads(encoded).value[0]

    countersignatures = decoded.countersignatures
    assert len(countersignatures) == 1

    cs = countersignatures[0]
    assert isinstance(cs, Countersignature)
    assert cs.get_attr(headers.Algorithm) == EdDSA
    assert cs.get_attr(headers.KID) == b'cs-kid'
    # raw protected header bytes of the received countersignature must be preserved
    assert cs.phdr_encoded == cbor2.loads(encoded).value[1][11][0][0]

    cs.key = countersign_key
    assert cs.verify_signature()

    assert decoded.verify_countersignatures(countersign_key)


def test_sign1_countersign0_roundtrip(sign_key, countersign_key):
    msg = _signed_sign1(sign_key)
    signature = msg.countersign0(countersign_key)

    assert msg.uhdr[headers.CounterSignature0V2] == signature

    decoded = CoseMessage.decode(msg.encode())

    cs0 = decoded.countersignature0
    assert cs0 is not None
    assert cs0.signature == signature

    cs0.key = countersign_key
    assert cs0.verify_signature()
    assert decoded.verify_countersignatures(countersign_key)


def test_sign1_multiple_countersignatures(sign_key, countersign_key):
    msg = _signed_sign1(sign_key)
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'})
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'}, unprotected={'KID': b'second'})

    decoded = CoseMessage.decode(msg.encode())

    assert len(decoded.countersignatures) == 2
    assert decoded.verify_countersignatures(countersign_key)


def test_sign1_tampered_payload_fails(sign_key, countersign_key):
    msg = _signed_sign1(sign_key)
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'})
    decoded = CoseMessage.decode(msg.encode())

    decoded.payload = _tamper(decoded.payload)

    assert not decoded.verify_countersignatures(countersign_key)

    # the failed countersignature must not be removed: the message stays inspectable
    assert len(decoded.countersignatures) == 1
    assert decoded.payload == _tamper(b'hello world')
    assert headers.Algorithm in decoded.phdr
    # verifying again must not suddenly succeed
    assert not decoded.verify_countersignatures(countersign_key)


def test_sign1_tampered_signature_fails(sign_key, countersign_key):
    msg = _signed_sign1(sign_key)
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'})
    decoded = CoseMessage.decode(msg.encode())

    # the version 2 countersignature covers the signature of the COSE_Sign1
    decoded.signature = _tamper(decoded.signature)

    assert not decoded.verify_countersignatures(countersign_key)
    assert len(decoded.countersignatures) == 1


def test_sign1_tampered_external_aad_fails(sign_key, countersign_key):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=b'hello world', external_aad=b'extra data')
    msg.key = sign_key
    msg.signature = msg.compute_signature()
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'})

    decoded = CoseMessage.decode(msg.encode())
    decoded.external_aad = b'extra data'
    assert decoded.verify_countersignatures(countersign_key)

    decoded.external_aad = b'other data'
    assert not decoded.verify_countersignatures(countersign_key)


def test_sign1_detached_payload_countersign(sign_key, countersign_key):
    msg = Sign1Message(phdr={'ALG': 'ES256'})
    msg.key = sign_key
    msg.signature = msg.compute_signature(detached_payload=b'detached content')
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'}, detached_payload=b'detached content')

    decoded = CoseMessage.decode(msg.encode(sign=False))
    assert decoded.payload is None

    assert decoded.verify_countersignatures(countersign_key, detached_payload=b'detached content')
    assert not decoded.verify_countersignatures(countersign_key, detached_payload=b'wrong content')


# --------------------------------------------------------------------------------------
# COSE_Sign
# --------------------------------------------------------------------------------------

def test_sign_single_signer_countersign_roundtrip(sign_key, countersign_key):
    msg = _signed_sign(sign_key)
    msg.signers[0].countersign(countersign_key, protected={'ALG': 'EDDSA'})

    decoded = CoseMessage.decode(msg.encode())
    decoded_signer = decoded.signers[0]

    assert len(decoded_signer.countersignatures) == 1
    assert decoded_signer.verify_countersignatures(countersign_key)

    # the original signature of the signer still verifies
    decoded_signer.key = sign_key
    assert decoded_signer.verify_signature()


def test_sign_single_signer_tampered_payload_fails(sign_key, countersign_key):
    msg = _signed_sign(sign_key)
    msg.signers[0].countersign(countersign_key, protected={'ALG': 'EDDSA'})

    decoded = CoseMessage.decode(msg.encode())
    decoded.payload = _tamper(decoded.payload)

    assert not decoded.signers[0].verify_countersignatures(countersign_key)
    assert len(decoded.signers[0].countersignatures) == 1


def test_sign_message_level_countersign_roundtrip(sign_key, countersign_key):
    msg = _signed_sign(sign_key)
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'})

    decoded = CoseMessage.decode(msg.encode())

    assert len(decoded.countersignatures) == 1
    assert decoded.verify_countersignatures(countersign_key)

    # tampering with a signer signature breaks the message-level countersignature
    decoded.signers[0].signature = _tamper(decoded.signers[0].signature)
    assert not decoded.verify_countersignatures(countersign_key)


# --------------------------------------------------------------------------------------
# COSE_Encrypt0
# --------------------------------------------------------------------------------------

def test_encrypt0_countersign_roundtrip(cek, countersign_key):
    msg = _encrypted_enc0(cek)
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'})
    msg.countersign0(countersign_key)

    decoded = CoseMessage.decode(msg.encode(encrypt=False))

    assert len(decoded.countersignatures) == 1
    assert decoded.countersignature0 is not None
    assert decoded.verify_countersignatures(countersign_key)

    # the ciphertext is covered by the countersignatures
    decoded.payload = _tamper(decoded.payload)
    assert not decoded.verify_countersignatures(countersign_key)
    assert len(decoded.countersignatures) == 1


# --------------------------------------------------------------------------------------
# COSE_Encrypt with multiple recipients
# --------------------------------------------------------------------------------------

def test_encrypt_multiple_recipients_countersign(countersign_key):
    recipients = [_wrapped_recipient(), _wrapped_recipient()]
    msg = EncMessage(phdr={'ALG': 'A256GCM', 'IV': os.urandom(12)},
                     payload=b'secret message',
                     recipients=recipients)
    msg.payload = msg.encrypt()
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'})

    decoded = CoseMessage.decode(msg.encode(encrypt=False))

    assert len(decoded.recipients) == 2
    assert decoded.verify_countersignatures(countersign_key)

    # recipient structures are not covered by the countersignature
    decoded.recipients[0].payload = _tamper(decoded.recipients[0].payload)
    assert decoded.verify_countersignatures(countersign_key)

    # the ciphertext is covered by the countersignature
    decoded.payload = _tamper(decoded.payload)
    assert not decoded.verify_countersignatures(countersign_key)


# --------------------------------------------------------------------------------------
# Interaction with RFC 8152 countersignature header parameters and unknown attributes
# --------------------------------------------------------------------------------------

def test_rfc8152_countersign_headers_are_not_v2(sign_key, countersign_key):
    msg = _signed_sign1(sign_key)
    msg.uhdr_update({headers.CounterSignature: b'\x00' * 64})
    msg.uhdr_update({headers.CounterSignature0: b'\x00' * 64})

    decoded = CoseMessage.decode(msg.encode())

    # the deprecated RFC 8152 header parameters must not be interpreted as V2 countersignatures
    assert decoded.countersignatures == []
    assert decoded.countersignature0 is None
    assert not decoded.verify_countersignatures(countersign_key)
    assert decoded.uhdr[headers.CounterSignature] == b'\x00' * 64
    assert decoded.uhdr[headers.CounterSignature0] == b'\x00' * 64


def test_unknown_unprotected_attribute_roundtrip(sign_key, countersign_key):
    msg = _signed_sign1(sign_key)
    msg.uhdr_update({65599: b'unknown-value'})
    msg.countersign(countersign_key, protected={'ALG': 'EDDSA'})

    decoded = CoseMessage.decode(msg.encode(), allow_unknown_attributes=True)

    assert decoded.uhdr[65599] == b'unknown-value'
    assert decoded.verify_countersignatures(countersign_key)

    # re-encoding keeps both the unknown attribute and the countersignature
    redecoded = CoseMessage.decode(decoded.encode(sign=False), allow_unknown_attributes=True)
    assert redecoded.uhdr[65599] == b'unknown-value'
    assert redecoded.verify_countersignatures(countersign_key)


def test_verify_countersignatures_without_countersignatures(sign_key, countersign_key):
    decoded = CoseMessage.decode(_signed_sign1(sign_key).encode())

    assert decoded.countersignatures == []
    assert decoded.countersignature0 is None
    assert not decoded.verify_countersignatures(countersign_key)


# --------------------------------------------------------------------------------------
# Independently constructed test vector (no pycose signing/verification code involved)
# --------------------------------------------------------------------------------------

def test_sign1_independent_countersignature_vector(sign_key):
    # build the Countersign_structure by hand and sign it directly with the cryptography library
    sk = Ed25519PrivateKey.generate()
    pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    verify_key = OKPKey(crv='ED25519', x=pk_bytes, optional_params={'ALG': 'EDDSA', 'KEY_OPS': ['VERIFY']})

    msg = _signed_sign1(sign_key)

    cs_protected = cbor2.dumps({headers.Algorithm.identifier: EdDSA.identifier})
    structure = cbor2.dumps([
        "CounterSignatureV2",
        msg.phdr_encoded,
        b'',
        msg.payload,
        [msg.signature],
    ])
    signature = sk.sign(structure)

    msg.uhdr_update({headers.CounterSignatureV2: [[cs_protected, {}, signature]]})

    decoded = CoseMessage.decode(msg.encode())
    assert decoded.verify_countersignatures(verify_key)

    # tampering with the payload must fail against the independently constructed vector
    decoded.payload = _tamper(decoded.payload)
    assert not decoded.verify_countersignatures(verify_key)


def test_sign1_pycose_countersignature_verified_independently(sign_key, countersign_key):
    msg = _signed_sign1(sign_key)
    cs = msg.countersign(countersign_key, protected={'ALG': 'EDDSA'})

    # verify the pycose-produced countersignature directly with the cryptography library
    structure = cbor2.dumps([
        "CounterSignatureV2",
        msg.phdr_encoded,
        b'',
        msg.payload,
        [msg.signature],
    ])
    Ed25519PublicKey.from_public_bytes(countersign_key.x).verify(cs.signature, structure)
