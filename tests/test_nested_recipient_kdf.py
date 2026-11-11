"""
Audit tests for two-layer (nested) COSE recipients and the per-layer KDF context.

Scenario under test (RFC 8152 Appendix B style)::

    COSE_Encrypt / COSE_Mac          (content layer, e.g. A128GCM / AES-MAC)
      └─ recipient (outer)           key wrap, e.g. A128KW  -> needs a 16-byte KEK
           └─ recipient (inner)      ECDH-ES/SS + HKDF      -> derives that KEK

The inner recipient's KDF context MUST name the *outer wrap algorithm* and carry
*its* key length (algorithm id -3 / 128 bits for A128KW), never the message-level
content algorithm (A128GCM, id 1). Every intermediate value is recomputed here with
an independent HKDF construction so a failure can be attributed to a specific layer
instead of surfacing as a generic decryption error.
"""
import cbor2
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

from pycose import headers
from pycose.algorithms import (
    A128GCM, A128KW, A192KW, A256KW,
    AESMAC128128, HMAC256,
    EcdhEsHKDF256, EcdhEsA128KW, EcdhEsA256KW, EcdhSsHKDF256,
    Direct, DirectHKDFSHA256,
)
from pycose.exceptions import CoseException
from pycose.keys.curves import P256
from pycose.keys.ec2 import EC2Key, EC2KpD, EC2KpX, EC2KpY
from pycose.keys.keyops import DecryptOp, MacVerifyOp
from pycose.keys.keyparam import EC2KpCurve, KpAlg, KpKeyOps, KpKty
from pycose.keys.keytype import KtyEC2
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.encmessage import EncMessage
from pycose.messages.macmessage import MacMessage
from pycose.messages.recipient import (
    CoseRecipient, DirectEncryption, DirectKeyAgreement, KeyWrap,
    KeyAgreementWithKeyWrap,
)

# Fixed key material so every derived value is reproducible.
EPHEMERAL_D = bytes(range(32))
RECEIVER_D = bytes(range(32, 64))


def _ec2_private(scalar: int) -> EC2Key:
    """Build a valid P-256 private key from a fixed 32-byte scalar."""
    priv = ec.derive_private_key(int.from_bytes(scalar, "big"), ec.SECP256R1(),
                                 default_backend())
    nums = priv.public_key().public_numbers()
    return EC2Key.from_dict({
        KpKty: KtyEC2,
        EC2KpCurve: P256,
        EC2KpX: nums.x.to_bytes(32, "big"),
        EC2KpY: nums.y.to_bytes(32, "big"),
        EC2KpD: scalar,
    })


@pytest.fixture(scope="module")
def eph_key() -> EC2Key:
    return _ec2_private(EPHEMERAL_D)


@pytest.fixture(scope="module")
def recv_key() -> EC2Key:
    return _ec2_private(RECEIVER_D)


def _ecdh_shared_secret(eph: EC2Key, recv: EC2Key) -> bytes:
    """Independent ECDH computation, not using pycose's internal routine."""
    priv = ec.derive_private_key(int.from_bytes(eph.d, "big"), ec.SECP256R1(),
                                 default_backend())
    peer = ec.EllipticCurvePublicNumbers(
        int.from_bytes(recv.x, "big"), int.from_bytes(recv.y, "big"),
        ec.SECP256R1()).public_key(default_backend())
    return priv.exchange(ec.ECDH(), peer)


def _independent_hkdf(shared_secret: bytes, context: bytes, length: int) -> bytes:
    """HKDF-SHA-256 with no salt, exactly as RFC 8152 prescribes for the KEK."""
    return HKDF(algorithm=SHA256(), length=length, salt=None, info=context,
                backend=default_backend()).derive(shared_secret)


def _inner_dka(eph_key, recv_key, alg=EcdhEsHKDF256, party_uhdr=None):
    uhdr = {headers.EphemeralKey: dict(eph_key), headers.KID: b"inner"}
    if party_uhdr:
        uhdr.update(party_uhdr)
    dka = DirectKeyAgreement(phdr={headers.Algorithm: alg}, uhdr=uhdr)
    dka.key = eph_key
    dka.local_attrs = {headers.StaticKey: recv_key}
    return dka


# --------------------------------------------------------------------------- #
# 1. KDF context construction: target algorithm id and key length             #
# --------------------------------------------------------------------------- #

def test_inner_context_names_outer_wrap_algorithm_not_content_alg(eph_key, recv_key):
    dka = _inner_dka(eph_key, recv_key)

    wrap_ctx = cbor2.loads(dka.get_kdf_context(A128KW).encode())
    content_ctx = cbor2.loads(dka.get_kdf_context(A128GCM).encode())

    # The inner KEK feeds A128KW: algorithm id -3 and 128-bit length.
    assert wrap_ctx[0] == A128KW.identifier == -3
    assert wrap_ctx[3][0] == 128
    # The message content algorithm is a different COSE algorithm and must not
    # leak into the inner context.
    assert content_ctx[0] == A128GCM.identifier == 1
    assert wrap_ctx[0] != content_ctx[0]


@pytest.mark.parametrize("wrap_alg", [A128KW, A192KW, A256KW])
def test_inner_context_key_length_tracks_wrap_alg(eph_key, recv_key, wrap_alg):
    dka = _inner_dka(eph_key, recv_key)
    ctx = cbor2.loads(dka.get_kdf_context(wrap_alg).encode())
    assert ctx[0] == wrap_alg.identifier
    assert ctx[3][0] == wrap_alg.get_key_length() * 8
    derived = dka.compute_cek(wrap_alg, "encrypt")
    assert len(derived.k) == wrap_alg.get_key_length()


def test_supp_pub_embeds_inner_protected_header(eph_key, recv_key):
    dka = _inner_dka(eph_key, recv_key)
    ctx = cbor2.loads(dka.get_kdf_context(A128KW).encode())
    # SuppPubInfo.protected = serialized protected header of the *inner* recipient.
    assert ctx[3][1] == dka.phdr_encoded
    assert ctx[3][1] == cbor2.dumps({headers.Algorithm.identifier:
                                     EcdhEsHKDF256.identifier})


# --------------------------------------------------------------------------- #
# 2. Independent intermediate values: shared secret, context, KEK             #
# --------------------------------------------------------------------------- #

def test_independent_kek_matches_library_per_layer(eph_key, recv_key):
    dka = _inner_dka(eph_key, recv_key)
    shared = _ecdh_shared_secret(eph_key, recv_key)

    # Inner layer: A128KW KEK.
    inner_ctx = dka.get_kdf_context(A128KW).encode()
    expected_kek = _independent_hkdf(shared, inner_ctx, A128KW.get_key_length())
    assert dka.compute_cek(A128KW, "encrypt").k == expected_kek

    # A wrong-layer context (content alg) yields a different key, proving the
    # context bytes actually drive the derivation and cannot be substituted.
    wrong_ctx = dka.get_kdf_context(A128GCM).encode()
    wrong_kek = _independent_hkdf(shared, wrong_ctx, A128GCM.get_key_length())
    assert wrong_kek != expected_kek


def test_layer_mismatch_is_localized_to_inner_context(eph_key, recv_key):
    """The two layers produce distinct contexts; a swap is detectable at the
    inner recipient before any content decryption is attempted."""
    dka = _inner_dka(eph_key, recv_key)
    inner_ctx = dka.get_kdf_context(A128KW).encode()
    content_ctx = dka.get_kdf_context(A128GCM).encode()
    assert inner_ctx != content_ctx

    shared = _ecdh_shared_secret(eph_key, recv_key)
    kek = _independent_hkdf(shared, inner_ctx, 16)
    # A 32-byte content-key derivation cannot be used as an A128WK KEK.
    with pytest.raises(ValueError):
        A128KW.key_wrap(SymmetricKey(k=_independent_hkdf(shared, content_ctx, 32)),
                        b"\xaa" * 16)
    assert len(kek) == 16


# --------------------------------------------------------------------------- #
# 3. PartyU / PartyV exchange and missing party information                    #
# --------------------------------------------------------------------------- #

def test_party_u_and_v_round_trip_into_context(eph_key, recv_key):
    party = {
        headers.PartyUID: b"alice", headers.PartyUNonce: b"\x01\x02",
        headers.PartyUOther: b"u-other",
        headers.PartyVID: b"bob", headers.PartyVNonce: b"\x03\x04",
        headers.PartyVOther: b"v-other",
    }
    dka = _inner_dka(eph_key, recv_key, party_uhdr=party)
    dka.local_attrs.update({headers.SuppPubOther: b"pub-other",
                            headers.SuppPrivOther: b"priv-secret"})
    ctx = cbor2.loads(dka.get_kdf_context(A128KW).encode())

    assert ctx[1] == [b"alice", b"\x01\x02", b"u-other"]   # PartyU
    assert ctx[2] == [b"bob", b"\x03\x04", b"v-other"]     # PartyV
    assert ctx[3] == [128, dka.phdr_encoded, b"pub-other"]  # SuppPubInfo
    assert ctx[4] == b"priv-secret"                        # SuppPrivInfo

    # Full CBOR round trip must preserve the party header parameters.
    outer = KeyWrap(uhdr={headers.Algorithm: A128KW},
                    key=dka.compute_cek(A128KW, "encrypt"),
                    payload=b"\xbb" * 16, recipients=[dka])
    encoded = outer.encode(target_alg=A128KW)
    wire = cbor2.dumps(cbor2.CBORTag(96, [b"", {}, b"x", [encoded]]),
                       default=outer._custom_cbor_encoder)
    decoded_outer = cbor2.loads(wire).value[3][0]
    parsed = CoseRecipient.create_recipient(decoded_outer, True,
                                            context="Rec_Recipient")
    inner = parsed.recipients[0]
    rebuilt = cbor2.loads(inner.get_kdf_context(A128KW).encode())
    assert rebuilt[1] == ctx[1]
    assert rebuilt[2] == ctx[2]


def test_missing_party_information_encodes_nil_triples(eph_key, recv_key):
    dka = _inner_dka(eph_key, recv_key)
    ctx = cbor2.loads(dka.get_kdf_context(A128KW).encode())
    assert ctx[1] == [None, None, None]
    assert ctx[2] == [None, None, None]
    # No fifth element when SuppPrivInfo is absent.
    assert len(ctx) == 4
    assert ctx[3] == [128, dka.phdr_encoded]


# --------------------------------------------------------------------------- #
# 4. Full two-layer Encrypt / Mac messages and end-to-end recovery            #
# --------------------------------------------------------------------------- #

def _build_nested_encrypt(eph_key, recv_key, content_alg=A128GCM, wrap_alg=A128KW):
    inner = _inner_dka(eph_key, recv_key)
    outer = KeyWrap(uhdr={headers.Algorithm: wrap_alg}, recipients=[inner])
    msg = EncMessage(
        phdr={headers.Algorithm: content_alg},
        uhdr={headers.IV: b"\x01" * 12},
        payload=b"This is the content.",
        recipients=[outer],
    )
    return msg, inner, outer


def test_nested_encrypt_round_trip_and_inner_context(eph_key, recv_key):
    captured = {}
    original = DirectKeyAgreement.get_kdf_context

    def spy(self, algorithm):
        captured["algorithm"] = algorithm
        captured["context"] = original(self, algorithm).encode()
        return original(self, algorithm)

    DirectKeyAgreement.get_kdf_context = spy
    try:
        msg, inner, outer = _build_nested_encrypt(eph_key, recv_key)
        wire = msg.encode()
    finally:
        DirectKeyAgreement.get_kdf_context = original

    # The library must have built the inner context against the outer wrap alg.
    assert captured["algorithm"] is A128KW
    ctx = cbor2.loads(captured["context"])
    assert ctx[0] == A128KW.identifier
    assert ctx[3][0] == 128

    # Independent check of the KEK that the wrap layer consumed.
    shared = _ecdh_shared_secret(eph_key, recv_key)
    expected_kek = _independent_hkdf(shared, captured["context"], 16)

    decoded = EncMessage.decode(wire)
    assert isinstance(decoded.recipients[0], KeyWrap)
    decoded_inner = decoded.recipients[0].recipients[0]
    assert isinstance(decoded_inner, DirectKeyAgreement)
    decoded_inner.key = recv_key

    # Receiver derives the same KEK through the shared recipient logic.
    recovered_kek = decoded_inner.compute_cek(A128KW, "decrypt").k
    assert recovered_kek == expected_kek

    plaintext = decoded.decrypt(decoded.recipients[0])
    assert plaintext == b"This is the content."


def test_nested_encrypt_wrong_receiver_key_fails_at_wrap_layer(eph_key, recv_key):
    msg, _, _ = _build_nested_encrypt(eph_key, recv_key)
    wire = msg.encode()
    decoded = EncMessage.decode(wire)
    outer = decoded.recipients[0]
    decoded_inner = outer.recipients[0]

    # Correct inner KEK first, for a baseline comparison.
    decoded_inner.key = recv_key
    correct_kek = decoded_inner.compute_cek(A128KW, "decrypt").k

    # A different static private key changes the ECDH shared secret and therefore
    # the inner-derived KEK; HKDF itself never fails, so the divergence is caught
    # by the outer AES key wrap (InvalidUnwrap), distinctly from any AEAD error.
    decoded_inner.key = _ec2_private(bytes(range(64, 96)))
    wrong_kek = decoded_inner.compute_cek(A128KW, "decrypt").k
    assert wrong_kek != correct_kek

    outer.key = SymmetricKey(k=wrong_kek,
                             optional_params={KpAlg: A128KW, KpKeyOps: [DecryptOp]})
    with pytest.raises(Exception):
        outer.decrypt(A128KW)


def test_nested_mac_round_trip_uses_same_recipient_logic(eph_key, recv_key):
    inner = _inner_dka(eph_key, recv_key)
    outer = KeyWrap(uhdr={headers.Algorithm: A128KW}, recipients=[inner])
    mac = MacMessage(phdr={headers.Algorithm: AESMAC128128}, uhdr={},
                     payload=b"authenticate me", recipients=[outer])
    wire = mac.encode()

    decoded = MacMessage.decode(wire)
    assert isinstance(decoded.recipients[0], KeyWrap)
    assert isinstance(decoded.recipients[0].recipients[0], DirectKeyAgreement)
    decoded.recipients[0].recipients[0].key = recv_key

    cek = decoded.recipients[0].compute_cek(AESMAC128128, "decrypt")
    decoded.key = SymmetricKey(k=cek.k,
                               optional_params={KpAlg: AESMAC128128,
                                                KpKeyOps: [MacVerifyOp]})
    assert decoded.verify_tag() is True

    # Corrupting the inner-derived CEK must invalidate the MAC tag.
    decoded.key = SymmetricKey(k=b"\x00" * len(cek.k),
                               optional_params={KpAlg: AESMAC128128,
                                                KpKeyOps: [MacVerifyOp]})
    assert decoded.verify_tag() is False


# --------------------------------------------------------------------------- #
# 5. Single-layer ECDH key agreement with key wrap (reference behaviour)      #
# --------------------------------------------------------------------------- #

def test_single_layer_kaw_context_uses_wrap_function(eph_key, recv_key):
    kaw = KeyAgreementWithKeyWrap(
        phdr={headers.Algorithm: EcdhEsA128KW},
        uhdr={headers.EphemeralKey: dict(eph_key)})
    kaw.key = eph_key
    kaw.local_attrs = {headers.StaticKey: recv_key}
    wrap_func = EcdhEsA128KW.get_key_wrap_func()
    ctx = cbor2.loads(kaw.get_kdf_context(wrap_func).encode())
    assert ctx[0] == A128KW.identifier
    assert ctx[3][0] == 128

    kaw256 = KeyAgreementWithKeyWrap(
        phdr={headers.Algorithm: EcdhEsA256KW},
        uhdr={headers.EphemeralKey: dict(eph_key)})
    kaw256.key = eph_key
    kaw256.local_attrs = {headers.StaticKey: recv_key}
    ctx256 = cbor2.loads(
        kaw256.get_kdf_context(EcdhEsA256KW.get_key_wrap_func()).encode())
    assert ctx256[0] == A256KW.identifier
    assert ctx256[3][0] == 256


# --------------------------------------------------------------------------- #
# 6. Explicit rejection of unsupported / under-specified combinations         #
# --------------------------------------------------------------------------- #

def test_direct_hkdf_recipient_is_explicitly_unsupported():
    recipient = DirectEncryption(
        uhdr={headers.Algorithm: DirectHKDFSHA256},
        key=SymmetricKey(k=b"\x11" * 32))
    with pytest.raises(NotImplementedError):
        recipient.compute_cek(A128KW)


def test_plain_direct_recipient_does_not_derive():
    recipient = DirectEncryption(uhdr={headers.Algorithm: Direct})
    assert recipient.compute_cek(A128KW) is None


def test_ecdh_ss_requires_static_sender_key(recv_key):
    ss = DirectKeyAgreement(phdr={headers.Algorithm: EcdhSsHKDF256}, uhdr={})
    ss.local_attrs = {headers.StaticKey: recv_key}
    with pytest.raises(CoseException, match="Static sender key"):
        ss.encode()


def test_hmac_content_alg_has_no_key_length_for_random_cek():
    # HMAC content algorithms expose no get_key_length, so the message layer
    # cannot fabricate a random CEK. The failure is loud (AttributeError) rather
    # than a silent fallback to an unrelated key; AES-MAC content algs, which do
    # define a key length, are the supported nested-MAC combination.
    assert not hasattr(HMAC256, "get_key_length")
    assert hasattr(AESMAC128128, "get_key_length")

    eph = EC2Key.generate_key(crv=P256)
    recv = EC2Key.generate_key(crv=P256)
    inner = _inner_dka(eph, recv)
    outer = KeyWrap(uhdr={headers.Algorithm: A128KW}, recipients=[inner])
    mac = MacMessage(phdr={headers.Algorithm: HMAC256}, uhdr={},
                     payload=b"x", recipients=[outer])
    with pytest.raises(AttributeError, match="get_key_length"):
        mac.encode()


def test_wrong_length_kek_rejected_by_wrap_layer():
    # A 32-byte key can never drive A128KW; this is the guard that makes a
    # content-algorithm/key-length mix-up fail at the outer layer.
    with pytest.raises(ValueError, match="wrong length"):
        A128KW.key_wrap(SymmetricKey(k=b"\x00" * 32), b"\xaa" * 16)


def test_nested_kw_generates_wrap_sized_random_key(eph_key, recv_key):
    # Nested KeyWrap -> KeyWrap must sample a KEK of the *outer* wrap length,
    # not pass the algorithm class into os.urandom.
    inner_kw = KeyWrap(uhdr={headers.Algorithm: A128KW},
                       key=SymmetricKey(k=b"\x22" * 16))
    outer_kw = KeyWrap(uhdr={headers.Algorithm: A256KW}, recipients=[inner_kw])
    kek_bytes = outer_kw._compute_kek(A256KW, "encrypt")
    assert len(kek_bytes) == A256KW.get_key_length() == 32


def test_nested_key_agreement_with_wrap_round_trip(eph_key, recv_key):
    # Outer A256KW wraps the CEK; an inner ECDH-ES+A128KW derives the 32-byte
    # outer KEK through its own KDF plus A128 key wrap.
    inner = KeyAgreementWithKeyWrap(
        phdr={headers.Algorithm: EcdhEsA128KW},
        uhdr={headers.EphemeralKey: dict(eph_key)})
    inner.key = eph_key
    inner.local_attrs = {headers.StaticKey: recv_key}
    outer = KeyWrap(uhdr={headers.Algorithm: A256KW}, recipients=[inner])
    msg = EncMessage(phdr={headers.Algorithm: A128GCM},
                     uhdr={headers.IV: b"\x02" * 12},
                     payload=b"kaw nested", recipients=[outer])
    decoded = EncMessage.decode(msg.encode())
    assert isinstance(decoded.recipients[0], KeyWrap)
    assert isinstance(decoded.recipients[0].recipients[0],
                      KeyAgreementWithKeyWrap)
    decoded.recipients[0].recipients[0].key = recv_key
    assert decoded.decrypt(decoded.recipients[0]) == b"kaw nested"


def test_nested_key_wrap_key_wrap_round_trip():
    # Two symmetric key-wrap layers; the outer KEK is sampled at 32 bytes and
    # itself wrapped under a 16-byte inner KEK.
    inner_kw = KeyWrap(uhdr={headers.Algorithm: A128KW},
                       key=SymmetricKey(k=b"\x33" * 16))
    outer_kw = KeyWrap(uhdr={headers.Algorithm: A256KW}, recipients=[inner_kw])
    msg = EncMessage(phdr={headers.Algorithm: A128GCM},
                     uhdr={headers.IV: b"\x03" * 12},
                     payload=b"kw nested", recipients=[outer_kw])
    decoded = EncMessage.decode(msg.encode())
    outer, inner = decoded.recipients[0], decoded.recipients[0].recipients[0]
    assert isinstance(outer, KeyWrap) and isinstance(inner, KeyWrap)
    inner.key = SymmetricKey(k=b"\x33" * 16)
    assert decoded.decrypt(outer) == b"kw nested"
