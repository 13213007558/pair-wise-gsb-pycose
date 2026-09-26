import os

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pycose import headers
from pycose.algorithms import EdDSA
from pycose.keys import EC2Key, OKPKey, SymmetricKey
from pycose.messages import Enc0Message, EncMessage, Sign1Message, SignMessage
from pycose.messages.countersignature import (
    CounterSignature0V2,
    CountersignatureV2,
    create_countersign_structure,
)
from pycose.messages.recipient import KeyWrap
from pycose.messages.signer import CoseSignature


def sign_key():
    return EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256', 'KEY_OPS': ['SIGN', 'VERIFY']})


def countersign_key():
    return OKPKey.generate_key(crv='ED25519', optional_params={'ALG': 'EDDSA', 'KEY_OPS': ['SIGN', 'VERIFY']})


def cek():
    return SymmetricKey.generate_key(32, optional_params={'ALG': 'A256GCM', 'KEY_OPS': ['ENCRYPT', 'DECRYPT']})


def make_sign1(key, payload=b'payload'):
    msg = Sign1Message(phdr={'ALG': 'ES256'}, payload=payload, key=key)
    msg.signature = msg.compute_signature()
    return msg


def make_sign_message(key, payload=b'payload'):
    cs_signer = CoseSignature(phdr={'ALG': 'ES256'}, key=key)
    msg = SignMessage(payload=payload, signers=[cs_signer])
    cs_signer.signature = cs_signer.compute_signature()
    return msg


def make_enc0(key, payload=b'secret'):
    msg = Enc0Message(phdr={'ALG': 'A256GCM', 'IV': os.urandom(12)}, payload=payload, key=key)
    msg.payload = msg.encrypt()
    return msg


def make_recipients(count=2):
    result = []
    for _ in range(count):
        key = SymmetricKey.generate_key(16, optional_params={'ALG': 'A128KW', 'KEY_OPS': ['WRAP', 'UNWRAP']})
        result.append(KeyWrap(uhdr={'ALG': 'A128KW'}, key=key))
    return result


def make_encrypt_message(recipients, payload=b'secret'):
    msg = EncMessage(phdr={'ALG': 'A256GCM', 'IV': os.urandom(12)}, payload=payload, recipients=recipients)
    msg.payload = msg.encrypt()
    return msg


def flip_last(value):
    return value[:-1] + bytes([value[-1] ^ 1])


def test_structure_sign1():
    key = sign_key()
    msg = make_sign1(key)

    assert create_countersign_structure('CounterSignatureV2', msg) == cbor2.dumps([
        'CounterSignatureV2', msg.phdr_encoded, b'', b'payload', [msg.signature]
    ])


def test_structure_sign_message():
    key = sign_key()
    msg = make_sign_message(key)

    assert create_countersign_structure('CounterSignatureV2', msg) == cbor2.dumps([
        'CounterSignatureV2',
        msg.phdr_encoded,
        b'',
        b'payload',
        [[s.signature for s in msg.signers]],
    ])


def test_structure_single_signer_contains_signature():
    key = sign_key()
    msg = make_sign_message(key)
    signer = msg.signers[0]

    assert create_countersign_structure('CounterSignatureV2', signer) == cbor2.dumps([
        'CounterSignatureV2', msg.phdr_encoded, signer.phdr_encoded, b'', b'payload', [signer.signature]
    ])


def test_structure_encrypt0():
    key = cek()
    msg = make_enc0(key)

    assert create_countersign_structure('CounterSignature0V2', msg) == cbor2.dumps([
        'CounterSignature0V2', msg.phdr_encoded, b'', msg.payload, []
    ])


def test_sign1_v2_roundtrip_preserves_raw_headers_and_unknown_attributes():
    key, cs_key = sign_key(), countersign_key()
    msg = make_sign1(key)
    msg.uhdr_update({65599: b'unknown'})
    cs = msg.countersign(cs_key, {'ALG': 'EDDSA'}, {'KID': b'cs'})

    encoded = msg.encode(sign=False)
    raw = cbor2.loads(encoded).value
    decoded = Sign1Message.decode(encoded)
    decoded_cs = decoded.countersignatures[0]

    assert len(decoded.countersignatures) == 1
    assert isinstance(decoded_cs, CountersignatureV2)
    assert decoded_cs.signature == cs.signature
    assert decoded_cs.get_attr(headers.KID) == b'cs'
    assert decoded.phdr_encoded == raw[0]
    assert decoded_cs.phdr_encoded == raw[1][headers.CounterSignatureV2.identifier][0][0]
    assert decoded.uhdr[65599] == b'unknown'
    assert decoded.verify_countersignatures(cs_key)

    redecoded = Sign1Message.decode(decoded.encode(sign=False))
    assert redecoded.uhdr[65599] == b'unknown'
    assert redecoded.verify_countersignatures(cs_key)


def test_sign1_counter_signature0_v2_roundtrip():
    key, cs_key = sign_key(), countersign_key()
    msg = make_sign1(key)
    cs0 = msg.countersign0(cs_key, {'ALG': 'EDDSA'}, {'KID': b'cs0', 65598: b'cs-unknown'})

    decoded = Sign1Message.decode(msg.encode(sign=False))
    raw = decoded.uhdr[headers.CounterSignature0V2]
    decoded_cs0 = decoded.counter_signature0_v2

    assert isinstance(raw, bytes)
    assert isinstance(decoded_cs0, CounterSignature0V2)
    assert decoded_cs0.signature == cs0.signature
    assert decoded_cs0.get_attr(headers.KID) == b'cs0'
    assert decoded_cs0.uhdr[65598] == b'cs-unknown'
    assert cbor2.loads(raw)[2] == b''
    assert decoded.verify_countersignatures(cs_key)


def test_single_signer_v2_roundtrip():
    key, cs_key = sign_key(), countersign_key()
    msg = make_sign_message(key)
    msg.signers[0].countersign(cs_key, {'ALG': 'EDDSA'})

    decoded = SignMessage.decode(msg.encode(sign=False))
    decoded_signer = decoded.signers[0]
    decoded_signer.key = key

    assert len(decoded_signer.countersignatures) == 1
    assert decoded_signer.verify_countersignatures(cs_key)
    assert decoded_signer.verify_signature()


def test_encrypt0_v2_roundtrip():
    enc_key, cs_key = cek(), countersign_key()
    msg = make_enc0(enc_key)
    msg.countersign0(cs_key, {'ALG': 'EDDSA'})

    decoded = Enc0Message.decode(msg.encode(encrypt=False))

    assert isinstance(decoded.counter_signature0_v2, CounterSignature0V2)
    assert decoded.verify_countersignatures(cs_key)


def test_encrypt_multiple_recipients_v2_roundtrip():
    cs_key = countersign_key()
    msg = make_encrypt_message(make_recipients(2))
    msg.countersign(cs_key, {'ALG': 'EDDSA'})

    decoded = EncMessage.decode(msg.encode(encrypt=False))

    assert len(decoded.recipients) == 2
    assert decoded.verify_countersignatures(cs_key)


def test_wrong_countersign_key_returns_false_and_keeps_header():
    key, cs_key, wrong_key = sign_key(), countersign_key(), countersign_key()
    msg = make_sign1(key)
    msg.countersign(cs_key, {'ALG': 'EDDSA'})
    decoded = Sign1Message.decode(msg.encode(sign=False))

    assert not decoded.verify_countersignatures(wrong_key)
    assert len(decoded.countersignatures) == 1


def test_tampered_sign1_payload_fails_without_removing_countersignature():
    key, cs_key = sign_key(), countersign_key()
    msg = make_sign1(key)
    msg.countersign(cs_key, {'ALG': 'EDDSA'})
    decoded = Sign1Message.decode(msg.encode(sign=False))
    decoded.payload = flip_last(decoded.payload)

    assert not decoded.verify_countersignatures(cs_key)
    assert len(decoded.countersignatures) == 1
    assert not decoded.verify_countersignatures(cs_key)


def test_tampered_sign1_signature_fails():
    key, cs_key = sign_key(), countersign_key()
    msg = make_sign1(key)
    msg.countersign(cs_key, {'ALG': 'EDDSA'})
    decoded = Sign1Message.decode(msg.encode(sign=False))
    decoded.signature = flip_last(decoded.signature)

    assert not decoded.verify_countersignatures(cs_key)
    assert len(decoded.countersignatures) == 1


def test_tampered_single_signer_signature_fails():
    key, cs_key = sign_key(), countersign_key()
    msg = make_sign_message(key)
    msg.signers[0].countersign(cs_key, {'ALG': 'EDDSA'})
    decoded = SignMessage.decode(msg.encode(sign=False))
    decoded.signers[0].signature = flip_last(decoded.signers[0].signature)

    assert not decoded.signers[0].verify_countersignatures(cs_key)
    assert len(decoded.signers[0].countersignatures) == 1


def test_tampered_single_signer_payload_fails():
    key, cs_key = sign_key(), countersign_key()
    msg = make_sign_message(key)
    msg.signers[0].countersign(cs_key, {'ALG': 'EDDSA'})
    decoded = SignMessage.decode(msg.encode(sign=False))
    decoded.payload = flip_last(decoded.payload)

    assert not decoded.signers[0].verify_countersignatures(cs_key)
    assert len(decoded.signers[0].countersignatures) == 1


def test_tampered_encrypt0_ciphertext_fails():
    enc_key, cs_key = cek(), countersign_key()
    msg = make_enc0(enc_key)
    msg.countersign(cs_key, {'ALG': 'EDDSA'})
    decoded = Enc0Message.decode(msg.encode(encrypt=False))
    decoded.payload = flip_last(decoded.payload)

    assert not decoded.verify_countersignatures(cs_key)
    assert len(decoded.countersignatures) == 1


def test_encrypt_recipient_field_is_not_covered_but_ciphertext_is():
    cs_key = countersign_key()
    msg = make_encrypt_message(make_recipients(2))
    msg.countersign(cs_key, {'ALG': 'EDDSA'})
    decoded = EncMessage.decode(msg.encode(encrypt=False))

    decoded.recipients[0].payload = flip_last(decoded.recipients[0].payload)
    assert decoded.verify_countersignatures(cs_key)

    decoded.payload = flip_last(decoded.payload)
    assert not decoded.verify_countersignatures(cs_key)
    assert len(decoded.countersignatures) == 1


def test_legacy_labels_do_not_impersonate_v2():
    key, cs_key = sign_key(), countersign_key()
    msg = make_sign1(key)
    msg.uhdr_update({headers.CounterSignature: b'old', headers.CounterSignature0: b'old0'})
    decoded = Sign1Message.decode(msg.encode(sign=False))

    assert decoded.countersignatures == []
    assert decoded.counter_signature0_v2 is None
    assert not decoded.verify_countersignatures(cs_key)
    assert decoded.uhdr[headers.CounterSignature] == b'old'
    assert decoded.uhdr[headers.CounterSignature0] == b'old0'


def test_independent_vector():
    key = sign_key()
    msg = make_sign1(key)
    ed25519_key = Ed25519PrivateKey.generate()
    public_bytes = ed25519_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    verify_key = OKPKey(crv='ED25519', x=public_bytes,
                        optional_params={'ALG': 'EDDSA', 'KEY_OPS': ['VERIFY']})
    cs_protected = cbor2.dumps({headers.Algorithm.identifier: EdDSA.identifier})
    to_be_signed = cbor2.dumps([
        'CounterSignatureV2', msg.phdr_encoded, b'', msg.payload, [msg.signature]
    ])
    msg.uhdr_update({headers.CounterSignatureV2: [[cs_protected, {}, ed25519_key.sign(to_be_signed)]]})

    decoded = Sign1Message.decode(msg.encode(sign=False))
    assert decoded.verify_countersignatures(verify_key)
    decoded.payload = flip_last(decoded.payload)
    assert not decoded.verify_countersignatures(verify_key)


def test_generated_signature_is_independently_verifiable():
    key, cs_key = sign_key(), countersign_key()
    msg = make_sign1(key)
    cs = msg.countersign(cs_key, {'ALG': 'EDDSA'})

    Ed25519PublicKey.from_public_bytes(cs_key.x).verify(
        cs.signature, create_countersign_structure('CounterSignatureV2', msg)
    )
