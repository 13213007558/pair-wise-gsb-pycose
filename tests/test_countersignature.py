"""
Tests for the RFC 9338 countersignatures (CounterSignatureV2 and CounterSignature0V2).
"""

from binascii import unhexlify

import cbor2
import pytest

from pycose.algorithms import Es256, A128GCM, A128KW
from pycose.exceptions import CoseException
from pycose.headers import Algorithm, KID, IV, CounterSignature, CounterSignature0, CounterSignatureV2, \
    CounterSignature0V2
from pycose.keys import EC2Key, SymmetricKey
from pycose.keys.keyops import EncryptOp, DecryptOp, WrapOp, UnwrapOp
from pycose.keys.keyparam import KpAlg, KpKeyOps
from pycose.messages import Sign1Message, SignMessage, Enc0Message, EncMessage, CoseCounterSignature, \
    CoseCounterSignature0
from pycose.messages.recipient import KeyWrap
from pycose.messages.signer import CoseSignature


@pytest.fixture
def signing_key():
    return EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})


@pytest.fixture
def countersign_key():
    return EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})


@pytest.fixture
def cek():
    return SymmetricKey(k=unhexlify('00' * 32), optional_params={KpAlg: A128GCM, KpKeyOps: [EncryptOp, DecryptOp]})


def test_countersign_sign1(signing_key, countersign_key):
    payload = b'payload to be countersigned'
    external_aad = b'some external aad'

    msg = Sign1Message(phdr={Algorithm: Es256}, payload=payload, external_aad=external_aad)
    msg.key = signing_key
    countersignature = CoseCounterSignature(phdr={Algorithm: Es256}, key=countersign_key)
    msg.uhdr_update({CounterSignatureV2: countersignature})

    encoded = msg.encode()

    # the Countersign_structure is built from the fields of the countersigned structure (RFC 9338, Section 3)
    expected_structure = cbor2.dumps([
        "CounterSignatureV2",
        msg.phdr_encoded,
        countersignature.phdr_encoded,
        external_aad,
        payload,
        [msg.signature],
    ])
    assert countersignature._create_sig_structure() == expected_structure
    assert Es256.verify(key=countersign_key, data=expected_structure, signature=countersignature.signature)

    # the wire format carries a single COSE_Countersignature structure under label 11
    raw = cbor2.loads(encoded).value
    assert raw[1][11] == [countersignature.phdr_encoded, {}, countersignature.signature]

    received = Sign1Message.decode(encoded)
    received.external_aad = external_aad
    cs_received = received.uhdr[CounterSignatureV2]
    assert isinstance(cs_received, CoseCounterSignature)
    assert received.countersignatures == [cs_received]

    cs_received.key = countersign_key
    assert cs_received._create_sig_structure() == expected_structure
    assert received.verify_countersignature(cs_received)


def test_countersign_sign1_tampered_payload(signing_key, countersign_key):
    msg = Sign1Message(phdr={Algorithm: Es256}, payload=b'payload to be countersigned')
    msg.key = signing_key
    msg.uhdr_update({CounterSignatureV2: CoseCounterSignature(phdr={Algorithm: Es256}, key=countersign_key)})

    received = Sign1Message.decode(msg.encode())
    cs_received = received.uhdr[CounterSignatureV2]
    cs_received.key = countersign_key
    assert received.verify_countersignature(cs_received)

    # the payload is covered by the countersignature
    received.payload = b'tampered payload'
    assert not received.verify_countersignature(cs_received)

    # a failed verification does not remove the countersignature nor breaks the message object
    assert received.countersignatures == [cs_received]
    assert CounterSignatureV2 in received.uhdr
    assert not received.verify_countersignature(cs_received)

    received.key = signing_key
    assert not received.verify_signature()


def test_countersign_sign1_tampered_signature(signing_key, countersign_key):
    msg = Sign1Message(phdr={Algorithm: Es256}, payload=b'payload to be countersigned')
    msg.key = signing_key
    msg.uhdr_update({CounterSignatureV2: CoseCounterSignature(phdr={Algorithm: Es256}, key=countersign_key)})

    received = Sign1Message.decode(msg.encode())
    cs_received = received.uhdr[CounterSignatureV2]
    cs_received.key = countersign_key

    # the signature of the COSE_Sign1 is covered by the countersignature (other_fields)
    received.signature = bytes([received.signature[0] ^ 0x01]) + received.signature[1:]
    assert not received.verify_countersignature(cs_received)
    assert received.countersignatures == [cs_received]


def test_countersign_multiple_on_sign1(signing_key):
    keys = [EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'}) for _ in range(2)]

    msg = Sign1Message(phdr={Algorithm: Es256}, payload=b'payload to be countersigned')
    msg.key = signing_key
    msg.uhdr_update({CounterSignatureV2: [CoseCounterSignature(phdr={Algorithm: Es256}, key=k) for k in keys]})

    # multiple countersignatures are encoded as an array of COSE_Countersignature structures
    raw = cbor2.loads(msg.encode()).value
    assert isinstance(raw[1][11], list) and len(raw[1][11]) == 2

    received = Sign1Message.decode(msg.encode())
    countersignatures = received.uhdr[CounterSignatureV2]
    assert len(countersignatures) == 2
    assert received.countersignatures == countersignatures

    for cs, key in zip(countersignatures, keys):
        cs.key = key
        assert received.verify_countersignature(cs)


def test_countersign0_sign1(signing_key, countersign_key):
    payload = b'payload to be countersigned'

    msg = Sign1Message(phdr={Algorithm: Es256}, payload=payload)
    msg.key = signing_key
    countersignature = CoseCounterSignature0(phdr={Algorithm: Es256}, key=countersign_key)
    msg.uhdr_update({CounterSignature0V2: countersignature})

    encoded = msg.encode()

    # the Countersign_structure for Countersignature0V2 has no sign_protected field
    expected_structure = cbor2.dumps([
        "CounterSignature0V2",
        msg.phdr_encoded,
        b'',
        payload,
        [msg.signature],
    ])
    assert countersignature._create_sig_structure() == expected_structure

    # the wire format carries a bare signature byte string under label 12
    raw = cbor2.loads(encoded).value
    assert isinstance(raw[1][12], bytes)

    received = Sign1Message.decode(encoded)
    cs_received = received.uhdr[CounterSignature0V2]
    assert isinstance(cs_received, CoseCounterSignature0)
    assert received.countersignatures == [cs_received]

    # algorithm and key are not transported and have to be supplied by the application
    cs_received.phdr_update({Algorithm: Es256})
    cs_received.key = countersign_key
    assert received.verify_countersignature(cs_received)

    received.payload = b'tampered payload'
    assert not received.verify_countersignature(cs_received)


def test_countersign_sign_signer(signing_key, countersign_key):
    payload = b'payload to be countersigned'

    signer = CoseSignature(phdr={Algorithm: Es256}, key=signing_key)
    countersignature = CoseCounterSignature(phdr={Algorithm: Es256}, key=countersign_key)
    signer.uhdr_update({CounterSignatureV2: countersignature})

    msg = SignMessage(phdr={}, payload=payload, signers=[signer])
    encoded = msg.encode()

    # the countersignature on a COSE_Signature covers the payload of the COSE_Sign and the signature
    expected_structure = cbor2.dumps([
        "CounterSignatureV2",
        signer.phdr_encoded,
        countersignature.phdr_encoded,
        b'',
        payload,
        [signer.signature],
    ])
    assert countersignature._create_sig_structure() == expected_structure

    received = SignMessage.decode(encoded)
    signer_received = received.signers[0]
    cs_received = signer_received.uhdr[CounterSignatureV2]
    assert isinstance(cs_received, CoseCounterSignature)
    cs_received.key = countersign_key
    assert cs_received._create_sig_structure() == expected_structure
    assert signer_received.verify_countersignature(cs_received)

    # tampering with the COSE_Sign payload invalidates the countersignature on the signer
    received.payload = b'tampered payload'
    assert not signer_received.verify_countersignature(cs_received)
    assert signer_received.countersignatures == [cs_received]


def test_countersign_enc0(cek, countersign_key):
    iv = unhexlify('00' * 12)
    msg = Enc0Message(phdr={Algorithm: A128GCM, IV: iv}, payload=b'secret payload', key=cek)
    countersignature = CoseCounterSignature(phdr={Algorithm: Es256}, key=countersign_key)
    msg.uhdr_update({CounterSignatureV2: countersignature})

    encoded = msg.encode()

    # the countersignature on a COSE_Encrypt0 covers the ciphertext; other_fields is empty
    ciphertext = cbor2.loads(encoded).value[2]
    expected_structure = cbor2.dumps([
        "CounterSignatureV2",
        msg.phdr_encoded,
        countersignature.phdr_encoded,
        b'',
        ciphertext,
        [],
    ])

    received = Enc0Message.decode(encoded)
    cs_received = received.uhdr[CounterSignatureV2]
    cs_received.key = countersign_key
    assert cs_received._create_sig_structure() == expected_structure
    assert received.verify_countersignature(cs_received)

    # the message can still be decrypted
    received.key = cek
    assert received.decrypt() == b'secret payload'

    # tampering with the ciphertext invalidates the countersignature
    received.payload = received.payload[:-1] + bytes([received.payload[-1] ^ 0x01])
    assert not received.verify_countersignature(cs_received)
    assert received.countersignatures == [cs_received]


def test_countersign_enc_multiple_recipients(countersign_key):
    kek1 = SymmetricKey(k=unhexlify('01' * 16),
                        optional_params={KpAlg: A128KW, KpKeyOps: [WrapOp, UnwrapOp, EncryptOp, DecryptOp]})
    kek2 = SymmetricKey(k=unhexlify('02' * 16),
                        optional_params={KpAlg: A128KW, KpKeyOps: [WrapOp, UnwrapOp, EncryptOp, DecryptOp]})

    recipients = [
        KeyWrap(uhdr={Algorithm: A128KW, KID: b'kid1'}, key=kek1),
        KeyWrap(uhdr={Algorithm: A128KW, KID: b'kid2'}, key=kek2),
    ]

    iv = unhexlify('00' * 12)
    msg = EncMessage(phdr={Algorithm: A128GCM, IV: iv}, payload=b'secret payload', recipients=recipients)
    msg.uhdr_update({CounterSignatureV2: CoseCounterSignature(phdr={Algorithm: Es256}, key=countersign_key)})

    encoded = msg.encode()

    received = EncMessage.decode(encoded)
    assert len(received.recipients) == 2

    cs_received = received.uhdr[CounterSignatureV2]
    cs_received.key = countersign_key
    assert received.verify_countersignature(cs_received)

    # the recipient structures are not covered by the countersignature
    received.recipients[1].payload = b'\x00' * len(received.recipients[1].payload)
    assert received.verify_countersignature(cs_received)

    # the message can still be decrypted through the untouched recipient
    received.recipients[0].key = kek1
    assert received.decrypt(received.recipients[0]) == b'secret payload'

    # tampering with the ciphertext invalidates the countersignature
    received.payload = received.payload[:-1] + bytes([received.payload[-1] ^ 0x01])
    assert not received.verify_countersignature(cs_received)
    assert received.countersignatures == [cs_received]


def test_countersign_preserved_protected_header(signing_key, countersign_key):
    # non-canonical (indefinite-length) encoding of the protected header {1: -7, 4: h'616263'}
    phdr_bytes = unhexlify('bf01260443616263ff')
    payload = b'countersigned payload'

    to_be_signed = cbor2.dumps(["Signature1", phdr_bytes, b'', payload])
    signature = Es256.sign(key=signing_key, data=to_be_signed)

    cs_phdr = cbor2.dumps({1: Es256.identifier})
    countersign_structure = cbor2.dumps(["CounterSignatureV2", phdr_bytes, cs_phdr, b'', payload, [signature]])
    cs_signature = Es256.sign(key=countersign_key, data=countersign_structure)

    cose_msg = cbor2.dumps(cbor2.CBORTag(18, [phdr_bytes, {11: [cs_phdr, {}, cs_signature]}, payload, signature]))

    received = Sign1Message.decode(cose_msg)

    # the raw bytes of the received protected header are preserved
    assert received.phdr_encoded == phdr_bytes

    received.key = signing_key
    assert received.verify_signature()

    cs_received = received.uhdr[CounterSignatureV2]
    cs_received.key = countersign_key
    assert cs_received._create_sig_structure() == countersign_structure
    assert received.verify_countersignature(cs_received)

    # re-encoding keeps the original protected header bytes
    assert phdr_bytes in received.encode(sign=False)


def test_countersign_unknown_uhdr_attribute_roundtrip(signing_key, countersign_key):
    msg = Sign1Message(phdr={Algorithm: Es256}, payload=b'payload')
    msg.key = signing_key
    msg.uhdr_update({
        -65537: b'unknown but allowed',
        CounterSignatureV2: CoseCounterSignature(phdr={Algorithm: Es256}, key=countersign_key),
    })

    received = Sign1Message.decode(msg.encode(), allow_unknown_attributes=True)
    assert received.uhdr[-65537] == b'unknown but allowed'

    cs_received = received.uhdr[CounterSignatureV2]
    cs_received.key = countersign_key
    assert received.verify_countersignature(cs_received)

    # the unknown attribute survives a re-encode
    re_encoded = received.encode(sign=False)
    assert cbor2.loads(re_encoded).value[1][-65537] == b'unknown but allowed'


def test_legacy_countersignature_labels_not_v2(signing_key):
    legacy_countersign = [b'', {}, b'legacy countersignature']

    msg = Sign1Message(phdr={Algorithm: Es256}, payload=b'payload')
    msg.key = signing_key
    msg.uhdr_update({CounterSignature: legacy_countersign, CounterSignature0: b'legacy countersignature0'})

    received = Sign1Message.decode(msg.encode())

    # the legacy (RFC 8152) countersignature attributes are not parsed as RFC 9338 countersignatures
    assert received.uhdr[CounterSignature] == legacy_countersign
    assert received.uhdr[CounterSignature0] == b'legacy countersignature0'
    assert received.countersignatures == []

    received.key = signing_key
    assert received.verify_signature()


def test_verify_countersignature_not_attached(signing_key, countersign_key):
    msg = Sign1Message(phdr={Algorithm: Es256}, payload=b'payload')
    msg.key = signing_key

    countersignature = CoseCounterSignature(phdr={Algorithm: Es256}, key=countersign_key)

    with pytest.raises(CoseException):
        msg.verify_countersignature(countersignature)


def test_countersignature_without_parent(countersign_key):
    countersignature = CoseCounterSignature(phdr={Algorithm: Es256}, key=countersign_key)

    with pytest.raises(CoseException):
        countersignature.compute_signature()
