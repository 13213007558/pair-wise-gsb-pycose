"""
Interoperability tests for the COSE_Sign / COSE_Sign1 Sig_structure.

The expected Sig_structure values in this module are constructed explicitly
from the CBOR data model (RFC 8152 sections 4.4 and 4.2) and the signatures
are checked with the low-level primitives of the ``cryptography`` package.

Neither the reference structures nor the verification go through pycose's
:meth:`SignCommon._create_sig_structure`, :meth:`SignCommon.compute_signature`
or :meth:`SignCommon.verify_signature`, so these tests cannot pass merely
because pycose agrees with itself.
"""

import cbor2
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from pycose.exceptions import CoseException
from pycose.headers import Algorithm, KID
from pycose.keys import EC2Key, OKPKey
from pycose.keys.keyops import SignOp, VerifyOp
from pycose.messages.sign1message import Sign1Message
from pycose.messages.signmessage import SignMessage
from pycose.messages.signer import CoseSignature

ES256 = -7
EDDSA = -8

# ---------------------------------------------------------------------------
# Independent reference helpers (no pycose signing/verification code is used)
# ---------------------------------------------------------------------------


def _ref_protected(parameters):
    """Serialize a protected header bucket exactly as it must appear on the wire."""
    if not parameters:
        return b""
    wire_header = {}
    for attribute, value in parameters.items():
        if hasattr(attribute, "identifier"):
            attribute = attribute.identifier
        if hasattr(value, "identifier"):
            value = value.identifier
        wire_header[attribute] = value
    return cbor2.dumps(wire_header)


def ref_sign_structure(body_protected, signer_protected, external_aad, payload):
    """Build the RFC 8152 section 4.4 COSE_Sign Sig_structure from scratch."""
    return cbor2.dumps([
        "Signature",
        _ref_protected(body_protected),
        _ref_protected(signer_protected),
        external_aad,
        payload,
    ])


def ref_sign1_structure(body_protected, external_aad, payload):
    """Build the RFC 8152 section 4.2 COSE_Sign1 Sig_structure from scratch."""
    return cbor2.dumps([
        "Signature1",
        _ref_protected(body_protected),
        external_aad,
        payload,
    ])


def _es256_public_key(ec2_key: EC2Key):
    x = int.from_bytes(ec2_key.x, "big")
    y = int.from_bytes(ec2_key.y, "big")
    return EllipticCurvePublicNumbers(x, y, ec2_key.crv.curve_obj).public_key()


def _raw_ecdsa_to_der(signature: bytes) -> bytes:
    component_len = len(signature) // 2
    r = int.from_bytes(signature[:component_len], "big")
    s = int.from_bytes(signature[component_len:], "big")
    return encode_dss_signature(r, s)


def independent_verify(algorithm, public_key, to_be_signed, signature):
    """Verify a signature using only cryptography primitives."""
    if algorithm == ES256:
        _es256_public_key(public_key).verify(
            _raw_ecdsa_to_der(signature), to_be_signed, ECDSA(hashes.SHA256()))
        return True
    if algorithm == EDDSA:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key.x).verify(signature, to_be_signed)
        return True
    raise ValueError(f"Unsupported test algorithm {algorithm}")


def independent_verify_fails(algorithm, public_key, to_be_signed, signature):
    try:
        independent_verify(algorithm, public_key, to_be_signed, signature)
    except InvalidSignature:
        return True
    return False


# ---------------------------------------------------------------------------
# Deterministic test keys
# ---------------------------------------------------------------------------


def _ec2_key():
    key = EC2Key.generate_key(crv="P_256", optional_params={"ALG": "ES256", "KEY_OPS": [SignOp, VerifyOp]})
    return key


def _okp_key():
    return OKPKey.generate_key(crv="ED25519", optional_params={"ALG": "EDDSA", "KEY_OPS": [SignOp, VerifyOp]})


EC2_KEY = _ec2_key()
OKP_KEY = _okp_key()

PAYLOAD = b"interoperability content"
EXTERNAL_AAD = b"external additional authenticated data"

# Each scenario pins down every slot of the five-element Sig_structure.
SIGN_SCENARIOS = [
    pytest.param(
        {}, {Algorithm: ES256}, PAYLOAD, b"", ES256, EC2_KEY,
        id="empty-body-protected-nonempty-signer-protected"),
    pytest.param(
        {KID: b"body"}, {}, PAYLOAD, b"", ES256, EC2_KEY,
        id="nonempty-body-protected-empty-signer-protected"),
    pytest.param(
        {}, {}, PAYLOAD, b"", ES256, EC2_KEY,
        id="both-protected-empty-algorithm-in-unprotected-header"),
    pytest.param(
        {KID: b"body"}, {Algorithm: ES256}, PAYLOAD, EXTERNAL_AAD, ES256, EC2_KEY,
        id="external-aad-with-both-protected-headers"),
    pytest.param(
        {}, {Algorithm: ES256}, b"", b"", ES256, EC2_KEY,
        id="empty-payload-bstr"),
    pytest.param(
        {}, {Algorithm: EDDSA}, PAYLOAD, EXTERNAL_AAD, EDDSA, OKP_KEY,
        id="eddsa-with-external-aad"),
]


def _build_sign_message(body_phdr, signer_phdr, payload, external_aad, algorithm, key):
    signer_uhdr = {} if signer_phdr else {Algorithm: algorithm}
    signer = CoseSignature(phdr=signer_phdr, uhdr=signer_uhdr, external_aad=external_aad)
    signer.key = key
    return SignMessage(phdr=body_phdr, payload=payload, signers=[signer]), signer


@pytest.mark.parametrize(
    "body_phdr, signer_phdr, payload, external_aad, algorithm, key",
    SIGN_SCENARIOS,
)
def test_sign_sig_structure_matches_independent_reference(
        body_phdr, signer_phdr, payload, external_aad, algorithm, key):
    msg, signer = _build_sign_message(body_phdr, signer_phdr, payload, external_aad, algorithm, key)

    expected = ref_sign_structure(body_phdr, signer_phdr, external_aad, payload)
    actual = signer._create_sig_structure()

    # The reference structure must always be the five-element RFC 8152 array.
    assert len(cbor2.loads(expected)) == 5
    assert actual == expected

    # The signature is checked with a fully independent cryptographic stack.
    signature = signer.compute_signature()
    assert independent_verify(algorithm, key, expected, signature)

    # A round-tripped message produces the identical structure and valid signature.
    decoded = SignMessage.decode(msg.encode())
    decoded_signer = decoded.signers[0]
    decoded_signer.external_aad = external_aad
    assert decoded_signer._create_sig_structure() == expected
    decoded_signer.key = key
    assert independent_verify(algorithm, key, expected, decoded_signer.signature)


@pytest.mark.parametrize(
    "body_phdr, signer_phdr, payload, external_aad, algorithm, key",
    SIGN_SCENARIOS,
)
def test_sign_structure_length_is_always_five(
        body_phdr, signer_phdr, payload, external_aad, algorithm, key):
    _, signer = _build_sign_message(body_phdr, signer_phdr, payload, external_aad, algorithm, key)

    structure = cbor2.loads(signer._create_sig_structure())
    assert structure[0] == "Signature"
    assert structure[1] == _ref_protected(body_phdr)
    assert structure[2] == _ref_protected(signer_phdr)
    assert structure[3] == external_aad
    assert structure[4] == payload
    assert len(structure) == 5


def test_multiple_signers_share_body_but_keep_own_sig_structure():
    first = CoseSignature(phdr={Algorithm: ES256}, external_aad=b"aad-one")
    first.key = EC2_KEY
    second = CoseSignature(phdr={}, uhdr={Algorithm: EDDSA}, external_aad=b"aad-two")
    second.key = OKP_KEY

    body_phdr = {KID: b"shared-body"}
    msg = SignMessage(phdr=body_phdr, payload=PAYLOAD, signers=[first, second])

    expected_first = ref_sign_structure(body_phdr, {Algorithm: ES256}, b"aad-one", PAYLOAD)
    expected_second = ref_sign_structure(body_phdr, {}, b"aad-two", PAYLOAD)

    assert first._create_sig_structure() == expected_first
    assert second._create_sig_structure() == expected_second

    encoded = msg.encode()
    decoded = SignMessage.decode(encoded)
    assert len(decoded.signers) == 2

    decoded.signers[0].external_aad = b"aad-one"
    decoded.signers[0].key = EC2_KEY
    decoded.signers[1].external_aad = b"aad-two"
    decoded.signers[1].key = OKP_KEY

    assert independent_verify(ES256, EC2_KEY, expected_first, decoded.signers[0].signature)
    assert independent_verify(EDDSA, OKP_KEY, expected_second, decoded.signers[1].signature)


def test_detached_payload_sig_structure_and_independent_verification():
    signer = CoseSignature(phdr={}, uhdr={Algorithm: ES256}, external_aad=EXTERNAL_AAD)
    signer.key = EC2_KEY
    msg = SignMessage(phdr={KID: b"detached"}, signers=[signer])

    encoded = msg.encode(detached_payload=PAYLOAD)
    decoded = SignMessage.decode(encoded)
    assert decoded.payload is None

    expected = ref_sign_structure({KID: b"detached"}, {}, EXTERNAL_AAD, PAYLOAD)
    decoded_signer = decoded.signers[0]
    decoded_signer.external_aad = EXTERNAL_AAD
    assert decoded_signer._create_sig_structure(detached_payload=PAYLOAD) == expected

    decoded_signer.key = EC2_KEY
    assert independent_verify(ES256, EC2_KEY, expected, decoded_signer.signature)


def test_nil_payload_without_detached_payload_is_rejected():
    signer = CoseSignature(phdr={Algorithm: ES256})
    signer.key = EC2_KEY
    msg = SignMessage(phdr={}, signers=[signer])

    with pytest.raises(CoseException, match="Missing payload"):
        msg.encode()


def test_detached_payload_rejected_when_inline_payload_present():
    signer = CoseSignature(phdr={Algorithm: ES256})
    signer.key = EC2_KEY
    msg = SignMessage(phdr={}, payload=PAYLOAD, signers=[signer])

    with pytest.raises(CoseException, match="Detached payload must be None"):
        msg.encode(detached_payload=PAYLOAD)


def test_sign1_uses_four_element_structure_with_own_reference():
    msg = Sign1Message(
        phdr={Algorithm: ES256, KID: b"sign1"},
        payload=PAYLOAD,
        external_aad=EXTERNAL_AAD)
    msg.key = EC2_KEY

    expected = ref_sign1_structure({Algorithm: ES256, KID: b"sign1"}, EXTERNAL_AAD, PAYLOAD)
    assert len(cbor2.loads(expected)) == 4
    assert msg._create_sig_structure() == expected

    decoded = Sign1Message.decode(msg.encode())
    decoded.external_aad = EXTERNAL_AAD
    decoded.key = EC2_KEY
    assert independent_verify(ES256, EC2_KEY, expected, decoded.signature)


def test_legacy_missing_signer_protected_slot_is_not_accepted():
    """Old pycose builds omitted the empty signer protected header; such
    malformed Sig_structures must no longer validate as standard messages."""
    signer = CoseSignature(phdr={}, uhdr={Algorithm: ES256})
    signer.key = EC2_KEY
    msg = SignMessage(phdr={KID: b"body"}, payload=PAYLOAD, signers=[signer])

    canonical = ref_sign_structure({KID: b"body"}, {}, b"", PAYLOAD)
    legacy = cbor2.dumps(["Signature", _ref_protected({KID: b"body"}), b"", PAYLOAD])

    assert len(cbor2.loads(legacy)) == 4
    assert canonical != legacy
    assert signer._create_sig_structure() == canonical

    signature = signer.compute_signature()
    # The signature is valid over the canonical structure and invalid over the legacy one.
    assert independent_verify(ES256, EC2_KEY, canonical, signature)
    assert independent_verify_fails(ES256, EC2_KEY, legacy, signature)


# ---------------------------------------------------------------------------
# CoseSignature attachment / reuse contract
# ---------------------------------------------------------------------------


def test_reusing_signer_across_messages_is_rejected_and_keeps_first_message():
    shared = CoseSignature(phdr={Algorithm: ES256})
    shared.key = EC2_KEY

    first = SignMessage(phdr={KID: b"first"}, payload=b"first payload", signers=[shared])
    assert shared._parent is first
    first_encoded = first.encode()

    second = SignMessage(phdr={KID: b"second"}, payload=b"second payload")
    with pytest.raises(CoseException, match="single SignMessage"):
        second.signers = [shared]

    # The rejected attachment must not silently retarget the original message.
    assert shared._parent is first
    assert second.signers == []
    assert first.encode() == first_encoded
    assert first.signers[0] is shared


def test_reusing_signer_in_constructor_is_rejected():
    shared = CoseSignature(phdr={Algorithm: ES256})
    shared.key = EC2_KEY
    SignMessage(phdr={}, payload=PAYLOAD, signers=[shared])

    with pytest.raises(CoseException, match="single SignMessage"):
        SignMessage(phdr={}, payload=b"other", signers=[shared])


def test_reattaching_signer_to_same_message_is_idempotent():
    signer = CoseSignature(phdr={Algorithm: ES256})
    signer.key = EC2_KEY
    msg = SignMessage(phdr={}, payload=PAYLOAD, signers=[signer])

    msg.signers = [signer]
    assert signer._parent is msg
    assert msg.signers == [signer]
    assert msg.encode()


def test_orphan_signer_reports_clear_contract_error():
    signer = CoseSignature(phdr={Algorithm: ES256})
    signer.key = EC2_KEY

    with pytest.raises(CoseException, match="attached to a SignMessage"):
        signer._create_sig_structure()


def test_signers_reject_non_list_and_wrong_element_type():
    msg = SignMessage(phdr={}, payload=PAYLOAD)
    with pytest.raises(CoseException, match="Signers must be of type list"):
        msg.signers = CoseSignature(phdr={Algorithm: ES256})

    with pytest.raises(CoseException, match="CoseSignature"):
        msg.signers = ["not a signer"]
