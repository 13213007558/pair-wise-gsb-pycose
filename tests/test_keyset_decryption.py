import os

import cbor2
import pytest
from cryptography.exceptions import InvalidTag

from pycose import headers
from pycose.algorithms import A128GCM, A128KW, A256KW, Direct
from pycose.exceptions import CoseException, CoseMalformedMessage, CoseNoMatchingKey
from pycose.keys.curves import P256, P384
from pycose.keys.ec2 import EC2Key
from pycose.keys.keyops import UnwrapOp, WrapOp
from pycose.keys.keyparam import KpAlg, KpKid, KpKeyOps
from pycose.keys.symmetric import SymmetricKey
from pycose.messages.encmessage import EncMessage
from pycose.messages.recipient import DirectEncryption, KeyWrap

PLAINTEXT = b'This is the content.'

KEK_LAYER_1 = bytes.fromhex('849b57219dae48de646d07dbb533566e')
KEK_LAYER_2 = bytes.fromhex('d9041b267e36d7ec791ab91cf0cad792')


def _wrap_key(kid: bytes, kek: bytes) -> SymmetricKey:
    return SymmetricKey(k=kek, optional_params={KpKid: kid, KpAlg: A128KW, KpKeyOps: [WrapOp, UnwrapOp]})


@pytest.fixture
def two_layer_message() -> bytes:
    inner = KeyWrap(uhdr={headers.Algorithm: A128KW, headers.KID: b'layer-2'},
                    key=_wrap_key(b'layer-2', KEK_LAYER_2))
    inner.payload = KEK_LAYER_1

    outer = KeyWrap(uhdr={headers.Algorithm: A128KW, headers.KID: b'layer-1'},
                    key=_wrap_key(b'layer-1', KEK_LAYER_1),
                    recipients=[inner])

    msg = EncMessage(phdr={headers.Algorithm: A128GCM},
                     uhdr={headers.IV: bytes.fromhex('c9cf4df2fe6c632bf7886413')},
                     payload=PLAINTEXT,
                     recipients=[outer])

    return msg.encode()


@pytest.fixture
def good_key() -> SymmetricKey:
    return _wrap_key(b'layer-2', KEK_LAYER_2)


@pytest.fixture
def bad_key() -> SymmetricKey:
    return SymmetricKey(k=os.urandom(16), optional_params={KpKeyOps: [UnwrapOp]})


def test_key_set_decryption_two_layer_wrap(two_layer_message, good_key, bad_key):
    msg = EncMessage.decode(two_layer_message)

    result = msg.decrypt_with_key_set([bad_key, good_key])

    assert result.plaintext == PLAINTEXT
    assert result.key is good_key
    assert result.kid == b'layer-2'
    assert result.recipient_path == [msg.recipients[0], msg.recipients[0].recipients[0]]


def test_key_set_decryption_key_order_does_not_matter(two_layer_message, good_key, bad_key):
    msg = EncMessage.decode(two_layer_message)

    result = msg.decrypt_with_key_set([good_key, bad_key])

    assert result.plaintext == PLAINTEXT
    assert result.key is good_key
    assert result.recipient_path == [msg.recipients[0], msg.recipients[0].recipients[0]]


def test_key_set_decryption_no_matching_key(two_layer_message, bad_key):
    msg = EncMessage.decode(two_layer_message)

    with pytest.raises(CoseNoMatchingKey):
        msg.decrypt_with_key_set([bad_key])


def test_key_set_decryption_content_authentication_failure(two_layer_message, good_key):
    msg = EncMessage.decode(two_layer_message)
    corrupted = bytearray(msg.payload)
    corrupted[0] ^= 1
    msg.payload = bytes(corrupted)

    # the CEK can be recovered but the content authentication fails: must be distinguishable
    # from the 'no usable key' case
    with pytest.raises(InvalidTag):
        msg.decrypt_with_key_set([good_key])


def test_key_set_decryption_conflicting_header_attributes(two_layer_message, good_key):
    msg = EncMessage.decode(two_layer_message)
    # conflicting algorithm in the protected and unprotected header bucket of the recipient
    msg.recipients[0].phdr = {headers.Algorithm: A256KW}

    with pytest.raises(CoseException) as exc_info:
        msg.decrypt_with_key_set([good_key])

    assert not isinstance(exc_info.value, CoseNoMatchingKey)


def test_key_set_decryption_illegal_recipient_combination(good_key):
    recipients = [DirectEncryption(uhdr={headers.Algorithm: Direct}),
                  KeyWrap(uhdr={headers.Algorithm: A128KW, headers.KID: b'layer-1'})]
    msg = EncMessage(phdr={headers.Algorithm: A128GCM}, recipients=recipients)

    with pytest.raises(CoseException) as exc_info:
        msg.decrypt_with_key_set([good_key])

    assert not isinstance(exc_info.value, CoseNoMatchingKey)


def test_key_set_decryption_without_recipients(good_key):
    msg = EncMessage(phdr={headers.Algorithm: A128GCM})

    with pytest.raises(CoseMalformedMessage):
        msg.decrypt_with_key_set([good_key])


def test_key_set_decryption_key_agreement_with_key_wrap(test_encrypt_key_agreement_key_wrap_files):
    test_input = test_encrypt_key_agreement_key_wrap_files['input']
    test_output = test_encrypt_key_agreement_key_wrap_files['output']

    msg = EncMessage.decode(cbor2.dumps(test_output['result']))
    receiver_key = test_input['recipients'][0]['static_receiver_key']

    # filtered out on the curve, never attempted
    wrong_curve_key = EC2Key.generate_key(P384)
    # right curve but the ECDH output does not unwrap the CEK
    wrong_key = EC2Key.generate_key(P256)

    result = msg.decrypt_with_key_set([wrong_curve_key, wrong_key, receiver_key])

    assert result.plaintext == test_input['plaintext']
    assert result.key is receiver_key
    assert result.kid == test_input['recipients'][0]['unprotected'][headers.KID]
    assert result.recipient_path == [msg.recipients[0]]
