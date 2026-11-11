"""
Fixed message vectors guarding the cbor2 5.x -> 6.x migration.

The vectors in ``tests/vectors/migration/migration-vectors.json`` are deterministic
(fixed keys, nonces and CEKs) and version-independent: they must decode and verify
identically with cbor2 5.x and cbor2 6.x. Regenerate them with
``tests/vectors/migration/gen_migration_vectors.py`` (never re-randomize in place).
"""
import json
import pathlib

import pytest

from pycose.keys import EC2Key, OKPKey, SymmetricKey
from pycose.keys.cosekey import CoseKey
from pycose.keys.keyops import VerifyOp, DecryptOp, MacVerifyOp, UnwrapOp
from pycose.keys.keyparam import KpAlg, KpKeyOps
from pycose.messages.cosemessage import CoseMessage
from pycose.messages.enc0message import Enc0Message
from pycose.messages.encmessage import EncMessage
from pycose.messages.mac0message import Mac0Message
from pycose.messages.macmessage import MacMessage
from pycose.messages.sign1message import Sign1Message
from pycose.messages.signmessage import SignMessage

VECTORS_FILE = pathlib.Path(__file__).parent / "vectors" / "migration" / "migration-vectors.json"
VECTORS = json.loads(VECTORS_FILE.read_text())

# fixed key material, identical to the generator script
EC_X = bytes.fromhex("be38079ed682fcebe05972ceabd5618549943319a1efb83737109a7d2a3cad6a")
EC_Y = bytes.fromhex("dbb73730772da84c0849c573cc6c094217739fcbc32c1e13e8e0761af46cc51a")
OKP_X = bytes.fromhex("828963aad668b92bf1ad755b63784aaaeb2bee6621d1cfb1a34dc80dda037dbf")
CEK = bytes.fromhex("00112233445566778899aabbccddeeff")
KEK = bytes.fromhex("ffeeddccbbaa99887766554433221100")

# protected header of the non-canonical sign1 vector: map(1) {1: -7} with a
# non-minimal 1-byte length encoding (0xb8 0x01) instead of the canonical 0xa1
NONCANONICAL_PHDR = bytes.fromhex("b8010126")


def ec_pub():
    return EC2Key.from_dict({1: 2, -1: 1, -2: EC_X, -3: EC_Y, 3: -7, 4: [VerifyOp]})


def okp_pub():
    return OKPKey.from_dict({1: 1, -1: 6, -2: OKP_X, 3: -8, 4: [VerifyOp]})


def sym(alg, ops, k=CEK):
    return SymmetricKey(k=k, optional_params={KpAlg: alg, KpKeyOps: ops})


def _run_positive(name, vector):
    raw = bytes.fromhex(vector["cbor"])

    if name == "cose_key":
        key = CoseKey.decode(raw)
        assert key.encode() == raw
        return

    payload = bytes.fromhex(vector["payload"])
    aad = bytes.fromhex(vector["external_aad"])
    msg = CoseMessage.decode(raw)

    if isinstance(msg, Sign1Message):
        msg.external_aad = aad
        msg.key = ec_pub() if name != "sign1_empty_phdr" else okp_pub()
        assert msg.verify_signature()

        if "cbor_noncanonical_phdr" in vector:
            # the raw protected header bytes (not a canonical re-encoding) must
            # feed the signature structure, otherwise this verification fails
            msg2 = CoseMessage.decode(bytes.fromhex(vector["cbor_noncanonical_phdr"]))
            msg2.external_aad = aad
            msg2.key = ec_pub()
            assert msg2.verify_signature()
            assert msg2.phdr_encoded == NONCANONICAL_PHDR

    elif isinstance(msg, SignMessage):
        assert len(msg.signers) == 2
        for signer, key in zip(msg.signers, [ec_pub(), okp_pub()]):
            signer.key = key
            assert signer.verify_signature()

    elif isinstance(msg, Enc0Message):
        msg.external_aad = aad
        msg.key = sym("A128GCM", [DecryptOp])
        assert msg.decrypt() == payload

    elif isinstance(msg, EncMessage):
        assert len(msg.recipients) == 1
        rcpt = msg.recipients[0]
        if name in ("enc_keywrap", "enc_nested_recipient"):
            rcpt.key = sym("A128KW", [UnwrapOp, DecryptOp], k=KEK)
        else:
            msg.key = sym("A128GCM", [DecryptOp])
        if name == "enc_nested_recipient":
            assert len(rcpt.recipients) == 1
            assert type(rcpt.recipients[0]).__name__ == "DirectEncryption"
        assert msg.decrypt(rcpt) == payload

    elif isinstance(msg, Mac0Message):
        msg.external_aad = aad
        msg.key = sym("HMAC_256_64", [MacVerifyOp])
        assert msg.verify_tag()

    elif isinstance(msg, MacMessage):
        msg.key = sym("HMAC_256_64", [MacVerifyOp])
        assert msg.verify_tag()

    else:
        raise AssertionError(f"unexpected message type {type(msg)}")


def _run_negative(vector):
    expected_exc = vector["expect"].split(":", 1)[1] if ":" in vector["expect"] else None
    with pytest.raises(Exception) as excinfo:
        CoseMessage.decode(bytes.fromhex(vector["cbor"]))
    if expected_exc:
        assert type(excinfo.value).__name__ == expected_exc


def _run_lenient(vector):
    msg = CoseMessage.decode(bytes.fromhex(vector["cbor"]))
    assert len(msg.recipients) == 0


@pytest.mark.parametrize("name,vector", sorted(VECTORS.items()), ids=sorted(VECTORS))
def test_migration_vector(name, vector):
    if vector["expect"].startswith("error"):
        _run_negative(vector)
    elif vector["expect"] == "accept_lenient":
        _run_lenient(vector)
    else:
        _run_positive(name, vector)
