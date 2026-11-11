"""
Cross-validation against RFC 8152 Appendix B (triple-layer example).

The repository copy of the vector at
tests/vectors/multi-layer-recipients/rfc8152-appendix-b.json is internally
inconsistent: its "secret" is not the ECDH shared secret and its outer key-wrap
ciphertext cannot be unwrapped with the RFC KEK. The authoritative fields
(context, CEK, content ciphertext, key pairs) are still valid and used here.
The KEK derived below matches RFC 8152 section B.1.4 exactly.
"""
import json
import pathlib

import cbor2
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

from pycose import headers
from pycose.algorithms import A128GCM, A128KW, EcdhEsHKDF256
from pycose.keys.curves import P256
from pycose.keys.ec2 import EC2Key
from pycose.keys.keyparam import EC2KpCurve, EC2KpD, EC2KpX, EC2KpY, KpKty
from pycose.keys.keytype import KtyEC2
from pycose.messages.encmessage import EncMessage
from pycose.messages.recipient import DirectKeyAgreement, KeyWrap

VECTOR = pathlib.Path(__file__).parent / "vectors" / "multi-layer-recipients" / \
         "rfc8152-appendix-b.json"
RFC_KEK = "3159efc5c0be8ebd4b7ef1b00cbe2dec"


@pytest.fixture(scope="module")
def rfc_data():
    data = json.loads(VECTOR.read_text())
    inner = data["input"]["recipients"][0]["recipients"][0]
    eph = EC2Key.from_dict({
        KpKty: KtyEC2, EC2KpCurve: P256,
        EC2KpX: bytes.fromhex(inner["ephemeral_sender_key"]["x"]),
        EC2KpY: bytes.fromhex(inner["ephemeral_sender_key"]["y"]),
        EC2KpD: bytes.fromhex(inner["ephemeral_sender_key"]["d"]),
    })
    recv = EC2Key.from_dict({
        KpKty: KtyEC2, EC2KpCurve: P256,
        EC2KpX: bytes.fromhex(inner["static_receiver_key"]["x"]),
        EC2KpY: bytes.fromhex(inner["static_receiver_key"]["y"]),
        EC2KpD: bytes.fromhex(inner["static_receiver_key"]["d"]),
    })
    return data, eph, recv


def _shared_secret(eph, recv):
    priv = ec.derive_private_key(int.from_bytes(eph.d, "big"),
                                 ec.SECP256R1(), default_backend())
    peer = ec.EllipticCurvePublicNumbers(
        int.from_bytes(recv.x, "big"), int.from_bytes(recv.y, "big"),
        ec.SECP256R1()).public_key(default_backend())
    return priv.exchange(ec.ECDH(), peer)


def test_library_context_matches_rfc_context(rfc_data):
    data, eph, recv = rfc_data
    dka = DirectKeyAgreement(phdr={headers.Algorithm: EcdhEsHKDF256},
                             uhdr={headers.KID: b"meriadoc"})
    dka.key = eph
    dka.local_attrs = {headers.StaticKey: recv}
    expected = data["output"]["recipients"][0]["recipients"][0]["context"]
    assert dka.get_kdf_context(A128KW).encode().hex() == expected.lower()
    ctx = cbor2.loads(bytes.fromhex(expected))
    assert ctx[0] == A128KW.identifier          # -3, not A128GCM (1)
    assert ctx[3][0] == 128                      # outer KEK length in bits


def test_independent_kek_equals_rfc_kek(rfc_data):
    data, eph, recv = rfc_data
    context = bytes.fromhex(
        data["output"]["recipients"][0]["recipients"][0]["context"])
    kek = HKDF(algorithm=SHA256(), length=16, salt=None, info=context,
               backend=default_backend()).derive(_shared_secret(eph, recv))
    assert kek.hex() == RFC_KEK


def test_full_message_round_trips_with_rfc_keys(rfc_data):
    data, eph, recv = rfc_data
    iv = bytes.fromhex(data["input"]["unprotected"]["iv"])

    inner = DirectKeyAgreement(
        phdr={headers.Algorithm: EcdhEsHKDF256},
        uhdr={headers.KID: b"meriadoc.brandybuck@buckland.example",
              headers.EphemeralKey: dict(eph)})
    inner.key = eph
    inner.local_attrs = {headers.StaticKey: recv}
    outer = KeyWrap(uhdr={headers.Algorithm: A128KW}, recipients=[inner])
    msg = EncMessage(phdr={headers.Algorithm: A128GCM},
                     uhdr={headers.IV: iv},
                     payload=data["input"]["plaintext"].encode(),
                     recipients=[outer])

    # The inner recipient derives the RFC KEK; the full nested flow then wraps
    # the freshly generated CEK and encrypts the content in one go.
    assert inner.compute_cek(A128KW, "encrypt").k.hex() == RFC_KEK
    wire = msg.encode()

    decoded = EncMessage.decode(wire)
    assert isinstance(decoded.recipients[0], KeyWrap)
    assert isinstance(decoded.recipients[0].recipients[0], DirectKeyAgreement)
    decoded.recipients[0].recipients[0].key = recv
    assert decoded.decrypt(decoded.recipients[0]) == \
        data["input"]["plaintext"].encode()
