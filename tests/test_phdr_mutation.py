"""
Tests for the protected header mutation contract.

Decoded COSE messages expose their header buckets as read-only views so that the
attributes observed by an application can never diverge from the bytes used by the
cryptographic operations (``phdr_encoded``). Modifications are only possible through
the controlled update paths (the ``phdr``/``uhdr`` setters and ``phdr_update``/
``uhdr_update``), which invalidate the cached encoded protected header.
"""
from binascii import unhexlify

import pytest
from cryptography.exceptions import InvalidTag

from pycose.algorithms import EdDSA, A128GCM, Es256
from pycose.headers import Algorithm, KID, IV, Critical
from pycose.keys import CoseKey
from pycose.keys.curves import Ed25519
from pycose.keys.keyops import SignOp, VerifyOp, EncryptOp, DecryptOp
from pycose.keys.keyparam import KpKty, KpKeyOps, OKPKpCurve, OKPKpD, OKPKpX, SymKpK
from pycose.keys.keytype import KtyOKP, KtySymmetric
from pycose.messages import Sign1Message, Enc0Message


@pytest.fixture
def sign1_key():
    return CoseKey.from_dict({
        KpKty: KtyOKP,
        OKPKpCurve: Ed25519,
        KpKeyOps: [SignOp, VerifyOp],
        OKPKpD: unhexlify(b'9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'),
        OKPKpX: unhexlify(b'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'),
    })


@pytest.fixture
def enc_key():
    return CoseKey.from_dict({
        KpKty: KtySymmetric,
        SymKpK: unhexlify(b'000102030405060708090a0b0c0d0e0f'),
        KpKeyOps: [EncryptOp, DecryptOp],
    })


@pytest.fixture
def signed_message(sign1_key):
    msg = Sign1Message(
        phdr={Algorithm: EdDSA, KID: b'kid2', Critical: [1, 'A']},
        payload=b'signed message')
    msg.key = sign1_key
    return msg.encode()


@pytest.fixture
def encrypted_message(enc_key):
    msg = Enc0Message(
        phdr={Algorithm: A128GCM, IV: b'000102030405060708090a0b0c'},
        uhdr={KID: b'kid1'},
        payload=b'some secret message')
    msg.key = enc_key
    return msg.encode()


# --- unmodified messages: original encoding preserved, verification works ---

def test_sign1_unmodified_preserves_encoding_and_verifies(signed_message, sign1_key):
    decoded = Sign1Message.decode(signed_message)

    # original protected header bytes are preserved
    assert decoded.encode(sign=False) == signed_message

    decoded.key = sign1_key
    assert decoded.verify_signature() is True


def test_enc0_unmodified_preserves_encoding_and_decrypts(encrypted_message, enc_key):
    decoded = Enc0Message.decode(encrypted_message)

    assert decoded.encode(encrypt=False) == encrypted_message

    decoded.key = enc_key
    assert decoded.decrypt() == b'some secret message'


def test_decoded_phdr_matches_original_encoding(signed_message):
    decoded = Sign1Message.decode(signed_message)
    import cbor2
    assert decoded.phdr_encoded == cbor2.dumps({1: -8, 4: b'kid2', 2: [1, 'A']})


# --- direct mutation of decoded headers is rejected ---

def test_sign1_direct_phdr_mutation_rejected(signed_message):
    decoded = Sign1Message.decode(signed_message)

    with pytest.raises(TypeError):
        decoded.phdr[Algorithm] = Es256

    with pytest.raises(TypeError):
        decoded.phdr[KID] = b'attacker'

    with pytest.raises(TypeError):
        del decoded.phdr[KID]

    with pytest.raises(AttributeError):
        decoded.phdr.update({KID: b'attacker'})

    with pytest.raises(AttributeError):
        decoded.phdr.pop(KID)

    # failed mutation attempts must not corrupt the cached encoding
    assert decoded.encode(sign=False) == signed_message


def test_sign1_nested_phdr_mutation_rejected(signed_message):
    decoded = Sign1Message.decode(signed_message)

    # nested mutable values reached through the view are immutable as well
    with pytest.raises((TypeError, AttributeError)):
        decoded.phdr[Critical].append(2)

    with pytest.raises(TypeError):
        decoded.phdr[Critical][0] = 3

    # values fetched through get_attr are equally read-only
    with pytest.raises((TypeError, AttributeError)):
        decoded.get_attr(Critical).append(2)

    assert decoded.encode(sign=False) == signed_message


def test_enc0_direct_header_mutation_rejected(encrypted_message):
    decoded = Enc0Message.decode(encrypted_message)

    with pytest.raises(TypeError):
        decoded.phdr[Algorithm] = Es256

    with pytest.raises(TypeError):
        decoded.uhdr[KID] = b'attacker'

    assert decoded.encode(encrypt=False) == encrypted_message


# --- controlled updates re-encode the protected header ---

def test_sign1_controlled_update_reencodes_and_invalidates_old_signature(signed_message, sign1_key):
    decoded = Sign1Message.decode(signed_message)
    decoded.key = sign1_key
    assert decoded.verify_signature() is True

    original_phdr_encoded = decoded.phdr_encoded
    decoded.phdr_update({KID: b'attacker'})

    # the cached encoding is invalidated and re-encoded from the visible attributes
    assert decoded.phdr_encoded != original_phdr_encoded
    assert decoded.phdr[KID] == b'attacker'

    # the old signature no longer authenticates the modified message
    assert decoded.verify_signature() is False
    assert decoded.encode(sign=False) != signed_message


def test_sign1_phdr_setter_reencodes_and_invalidates_old_signature(signed_message, sign1_key):
    decoded = Sign1Message.decode(signed_message)
    decoded.key = sign1_key

    decoded.phdr = {Algorithm: EdDSA, KID: b'attacker'}

    assert decoded.phdr[KID] == b'attacker'
    assert decoded.verify_signature() is False


def test_enc0_controlled_update_breaks_old_authentication(encrypted_message, enc_key):
    decoded = Enc0Message.decode(encrypted_message)
    decoded.key = enc_key
    assert decoded.decrypt() == b'some secret message'

    decoded.phdr_update({KID: b'attacker'})

    # the ciphertext was authenticated under the original protected header:
    # decryption must fail instead of accepting the modified message
    with pytest.raises(InvalidTag):
        decoded.decrypt()


def test_controlled_update_accepts_read_only_views(signed_message):
    decoded = Sign1Message.decode(signed_message)

    # views obtained from one message can be used to update another
    other = Sign1Message(phdr={Algorithm: EdDSA}, payload=b'other')
    other.phdr_update(decoded.phdr)
    assert other.phdr[KID] == b'kid2'
    assert other.phdr[Critical] == [1, 'A']

    other.phdr = decoded.phdr
    assert other.phdr[KID] == b'kid2'


# --- constructor isolation ---

def test_constructor_copies_header_buckets():
    crit = [1, 'A']
    uhdr = {KID: b'kid1'}
    msg = Sign1Message(phdr={Algorithm: EdDSA, Critical: crit}, uhdr=uhdr, payload=b'data')

    # later mutations of the caller's objects must not leak into the message
    crit.append(2)
    uhdr[KID] = b'attacker'

    assert msg.phdr[Critical] == [1, 'A']
    assert msg.uhdr[KID] == b'kid1'
