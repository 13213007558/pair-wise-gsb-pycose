import os

import pytest

from pycose import headers
from pycose.algorithms import A128KW, A256KW, A128GCM, EcdhEsA128KW
from pycose.exceptions import CoseException, CoseNoUsableKey, CoseContentAuthenticationFailed
from pycose.keys.curves import P256, P384
from pycose.keys.ec2 import EC2Key
from pycose.keys.keyops import EncryptOp, DecryptOp, WrapOp, UnwrapOp, DeriveKeyOp
from pycose.keys.keyparam import KpAlg, KpKeyOps, KpKid
from pycose.keys.symmetric import SymmetricKey
from pycose.messages import CoseMessage
from pycose.messages.enccommon import EncCommon
from pycose.messages.encmessage import EncMessage
from pycose.messages.recipient import KeyWrap, KeyAgreementWithKeyWrap

PLAINTEXT = b'a secret message for multiple recipients'


def _content_key(cek: bytes, key_ops) -> SymmetricKey:
    return SymmetricKey(k=cek, optional_params={KpAlg: A128GCM, KpKeyOps: key_ops})


def _build_two_layer_wrap_message():
    """
    Build a COSE_Encrypt message where the CEK is wrapped by an intermediate KEK (A256KW), which is itself
    wrapped by the recipient key (A128KW, kid=b'user-key').
    """
    user_kek = SymmetricKey.generate_key(16, optional_params={KpAlg: A128KW,
                                                              KpKeyOps: [WrapOp, UnwrapOp],
                                                              KpKid: b'user-key'})
    kek_bytes = os.urandom(32)
    cek = os.urandom(16)

    inner = KeyWrap(uhdr={headers.Algorithm: A128KW, headers.KID: b'user-key'})
    inner.key = user_kek
    inner.payload = kek_bytes

    outer = KeyWrap(uhdr={headers.Algorithm: A256KW}, recipients=[inner])
    outer.key = SymmetricKey(k=kek_bytes)
    outer.payload = cek

    msg = EncMessage(phdr={headers.Algorithm: A128GCM, headers.IV: os.urandom(12)},
                     payload=PLAINTEXT,
                     recipients=[outer])
    msg.key = _content_key(cek, [EncryptOp])
    msg.payload = EncCommon.encrypt(msg)

    return msg.encode(encrypt=False), user_kek


def _bad_user_key() -> SymmetricKey:
    # passes all filters (kid, alg, key_ops) but has the wrong key bytes
    return SymmetricKey.generate_key(16, optional_params={KpAlg: A128KW,
                                                          KpKeyOps: [UnwrapOp],
                                                          KpKid: b'user-key'})


def test_key_set_decrypt_two_layer_wrap():
    encoded, user_kek = _build_two_layer_wrap_message()
    msg = CoseMessage.decode(encoded)

    result = msg.decrypt_with_key_set([_bad_user_key(), user_kek])

    assert result.plaintext == PLAINTEXT
    assert result.kid == b'user-key'
    assert result.recipients == (msg.recipients[0], msg.recipients[0].recipients[0])


def test_key_set_decrypt_key_order_does_not_matter():
    encoded, user_kek = _build_two_layer_wrap_message()

    result_1 = CoseMessage.decode(encoded).decrypt_with_key_set([_bad_user_key(), user_kek])
    result_2 = CoseMessage.decode(encoded).decrypt_with_key_set([user_kek, _bad_user_key()])

    assert result_1.plaintext == result_2.plaintext == PLAINTEXT
    assert result_1.kid == result_2.kid == b'user-key'


def test_key_set_decrypt_no_usable_key():
    encoded, _ = _build_two_layer_wrap_message()
    msg = CoseMessage.decode(encoded)

    with pytest.raises(CoseNoUsableKey):
        msg.decrypt_with_key_set([_bad_user_key()])


def test_key_set_decrypt_filters_candidates():
    encoded, _ = _build_two_layer_wrap_message()

    wrong_kid = SymmetricKey.generate_key(16, optional_params={KpAlg: A128KW,
                                                               KpKeyOps: [UnwrapOp],
                                                               KpKid: b'other-key'})
    wrong_alg = SymmetricKey.generate_key(32, optional_params={KpAlg: A256KW,
                                                               KpKeyOps: [UnwrapOp],
                                                               KpKid: b'user-key'})
    wrong_ops = SymmetricKey.generate_key(16, optional_params={KpAlg: A128KW,
                                                               KpKeyOps: [EncryptOp],
                                                               KpKid: b'user-key'})

    with pytest.raises(CoseNoUsableKey):
        CoseMessage.decode(encoded).decrypt_with_key_set([wrong_kid, wrong_alg, wrong_ops])


def test_key_set_decrypt_content_authentication_failure():
    encoded, user_kek = _build_two_layer_wrap_message()
    msg = CoseMessage.decode(encoded)

    # tamper with the content ciphertext (authentication tag)
    tampered = bytearray(msg.payload)
    tampered[-1] ^= 0x01
    msg.payload = bytes(tampered)

    with pytest.raises(CoseContentAuthenticationFailed):
        msg.decrypt_with_key_set([user_kek])


def test_key_set_decrypt_conflicting_headers_are_reported():
    encoded, user_kek = _build_two_layer_wrap_message()
    msg = CoseMessage.decode(encoded)

    # same attribute in the protected and unprotected bucket of the inner recipient
    msg.recipients[0].recipients[0].phdr_update({headers.KID: b'user-key'})

    with pytest.raises(CoseException) as exc_info:
        msg.decrypt_with_key_set([user_kek])

    assert not isinstance(exc_info.value, CoseNoUsableKey)


def test_key_set_decrypt_key_agreement():
    receiver_key = EC2Key.generate_key(P256, optional_params={KpKeyOps: [DeriveKeyOp], KpKid: b'receiver'})
    receiver_public = EC2Key(crv=P256, x=receiver_key.x, y=receiver_key.y)

    cek = os.urandom(16)
    recipient = KeyAgreementWithKeyWrap(uhdr={headers.Algorithm: EcdhEsA128KW})
    recipient.local_attrs = {headers.StaticKey: receiver_public}
    recipient.payload = cek

    msg = EncMessage(phdr={headers.Algorithm: A128GCM, headers.IV: os.urandom(12)},
                     payload=PLAINTEXT,
                     recipients=[recipient])
    msg.key = _content_key(cek, [EncryptOp])
    msg.payload = EncCommon.encrypt(msg)
    encoded = msg.encode(encrypt=False)

    bad_key = EC2Key.generate_key(P256, optional_params={KpKeyOps: [DeriveKeyOp]})
    wrong_curve = EC2Key.generate_key(P384, optional_params={KpKeyOps: [DeriveKeyOp]})

    decoded = CoseMessage.decode(encoded)
    result = decoded.decrypt_with_key_set([wrong_curve, bad_key, receiver_key])

    assert result.plaintext == PLAINTEXT
    assert result.kid == b'receiver'
    assert result.recipients == (decoded.recipients[0],)
