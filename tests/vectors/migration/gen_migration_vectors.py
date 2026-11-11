"""Regenerate migration-vectors.json (deterministic: fixed keys, nonces and CEKs).

Run from any cbor2 version supported by pycose; the output must be byte-identical.
"""
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, REPO_ROOT)

import cbor2  # noqa: E402

from pycose.keys import EC2Key, OKPKey, SymmetricKey  # noqa: E402
from pycose.keys.keyops import SignOp, VerifyOp, EncryptOp, DecryptOp, MacCreateOp, MacVerifyOp, WrapOp, UnwrapOp  # noqa: E402
from pycose.keys.keyparam import KpAlg, KpKeyOps, KpKid  # noqa: E402
from pycose.messages.sign1message import Sign1Message  # noqa: E402
from pycose.messages.signmessage import SignMessage  # noqa: E402
from pycose.messages.signer import CoseSignature  # noqa: E402
from pycose.messages.enc0message import Enc0Message  # noqa: E402
from pycose.messages.encmessage import EncMessage  # noqa: E402
from pycose.messages.mac0message import Mac0Message  # noqa: E402
from pycose.messages.macmessage import MacMessage  # noqa: E402
from pycose.messages.recipient import DirectEncryption, KeyWrap  # noqa: E402
from pycose import headers  # noqa: E402

EC_X = bytes.fromhex("be38079ed682fcebe05972ceabd5618549943319a1efb83737109a7d2a3cad6a")
EC_Y = bytes.fromhex("dbb73730772da84c0849c573cc6c094217739fcbc32c1e13e8e0761af46cc51a")
EC_D = bytes.fromhex("66da632473a4fd87cb187cadebe2b5520cd72c75da6747002d76a5f9b405169b")
OKP_X = bytes.fromhex("828963aad668b92bf1ad755b63784aaaeb2bee6621d1cfb1a34dc80dda037dbf")
OKP_D = bytes.fromhex("bafe6631fbece16f522a013263b40c46cc8d3207d144c96913d428cb3aa6f026")

CEK = bytes.fromhex("00112233445566778899aabbccddeeff")
KEK = bytes.fromhex("ffeeddccbbaa99887766554433221100")
IV = bytes.fromhex("0102030405060708090a0b0c")
AAD = bytes.fromhex("aabbcc")
PAYLOAD = b"fixed migration vector payload"


def ec_priv():
    return EC2Key.from_dict({1: 2, -1: 1, -2: EC_X, -3: EC_Y, -4: EC_D, 3: -7, 4: [SignOp, VerifyOp]})


def ec_pub():
    return EC2Key.from_dict({1: 2, -1: 1, -2: EC_X, -3: EC_Y, 3: -7, 4: [VerifyOp]})


def okp_priv():
    return OKPKey.from_dict({1: 1, -1: 6, -2: OKP_X, -4: OKP_D, 3: -8, 4: [SignOp, VerifyOp]})


def okp_pub():
    return OKPKey.from_dict({1: 1, -1: 6, -2: OKP_X, 3: -8, 4: [VerifyOp]})


def sym_key(alg, ops, k=CEK):
    return SymmetricKey(k=k, optional_params={KpAlg: alg, KpKeyOps: ops})


vectors = {}

# --- V1: Sign1, ES256, non-canonical protected header (non-minimal length encoding) ---
msg = Sign1Message(phdr={"ALG": "ES256"}, payload=PAYLOAD, external_aad=AAD)
msg.key = ec_priv()
enc1 = msg.encode()
enc2 = Sign1Message(phdr={"ALG": "ES256"}, payload=PAYLOAD, external_aad=AAD)
enc2.key = ec_priv()
assert enc1 == enc2.encode(), "ES256 signing is not deterministic"
# Non-canonical protected header: map length encoded with 1-byte length (0xb8 0x01)
# instead of the minimal 0xa1. The decoded map is identical, but the raw bytes differ.
# The signature is computed over the NON-canonical encoding: verification only succeeds
# if the raw protected-header bytes (not a canonical re-encoding) feed the sig structure.
from pycose.algorithms import Es256  # noqa: E402

phdr_nonminimal = b"\xb8\x01\x01\x26"  # map(1) {1: -7} with non-minimal length
assert cbor2.loads(phdr_nonminimal) == {1: -7}
sig_structure = cbor2.dumps(["Signature1", phdr_nonminimal, AAD, PAYLOAD])
sig = Es256.sign(key=ec_priv(), data=sig_structure)
noncanon = cbor2.dumps(cbor2.CBORTag(18, [phdr_nonminimal, {}, PAYLOAD, sig]))
vectors["sign1_es256"] = {
    "cbor": enc1.hex(),
    "cbor_noncanonical_phdr": noncanon.hex(),
    "payload": PAYLOAD.hex(),
    "external_aad": AAD.hex(),
    "expect": "verify",
}

# --- V2: Sign1 with unknown (unregistered) header attribute ---
msg = Sign1Message(phdr={"ALG": "ES256"}, uhdr={4711: b"unknown-value"}, payload=PAYLOAD, external_aad=AAD)
msg.key = ec_priv()
vectors["sign1_unknown_header"] = {
    "cbor": msg.encode().hex(),
    "payload": PAYLOAD.hex(),
    "external_aad": AAD.hex(),
    "expect": "verify",
}

# --- V3: Sign1 with empty protected header ---
msg = Sign1Message(phdr={}, uhdr={"ALG": "EdDSA"}, payload=PAYLOAD)
msg.key = okp_priv()
vectors["sign1_empty_phdr"] = {
    "cbor": msg.encode().hex(),
    "payload": PAYLOAD.hex(),
    "external_aad": "",
    "expect": "verify",
}

# --- V4: COSE_Sign with two signers (ES256 + EdDSA) ---
msg = SignMessage(phdr={}, uhdr={}, payload=PAYLOAD)
s1 = CoseSignature(phdr={"ALG": "ES256"}, key=ec_priv())
s2 = CoseSignature(phdr={"ALG": "EdDSA"}, key=okp_priv())
msg.signers = [s1, s2]
vectors["sign_two_signers"] = {
    "cbor": msg.encode().hex(),
    "payload": PAYLOAD.hex(),
    "external_aad": "",
    "expect": "verify",
}

# --- V5: Encrypt0 AES-GCM ---
msg = Enc0Message(phdr={"ALG": "A128GCM"}, uhdr={"IV": IV}, payload=PAYLOAD, external_aad=AAD)
msg.key = sym_key("A128GCM", [EncryptOp, DecryptOp])
vectors["enc0_a128gcm"] = {
    "cbor": msg.encode().hex(),
    "payload": PAYLOAD.hex(),
    "external_aad": AAD.hex(),
    "expect": "decrypt",
}

# --- V6: COSE_Encrypt, direct encryption recipient ---
rcpt = DirectEncryption(uhdr={"ALG": "DIRECT", "KID": b"our-secret"})
msg = EncMessage(phdr={"ALG": "A128GCM"}, uhdr={"IV": IV}, payload=PAYLOAD, recipients=[rcpt])
msg.key = sym_key("A128GCM", [EncryptOp, DecryptOp])
vectors["enc_direct"] = {
    "cbor": msg.encode().hex(),
    "payload": PAYLOAD.hex(),
    "external_aad": "",
    "expect": "decrypt",
}

# --- V7: COSE_Encrypt with A128KW recipient ---
rcpt = KeyWrap(uhdr={"ALG": "A128KW"})
rcpt.key = SymmetricKey(k=KEK, optional_params={KpAlg: "A128KW", KpKeyOps: [WrapOp, UnwrapOp]})
rcpt.payload = CEK
msg = EncMessage(phdr={"ALG": "A128GCM"}, uhdr={"IV": IV}, payload=PAYLOAD, recipients=[rcpt])
msg.key = sym_key("A128GCM", [EncryptOp, DecryptOp])
enc = msg.encode(encrypt=True)
vectors["enc_keywrap"] = {
    "cbor": enc.hex(),
    "payload": PAYLOAD.hex(),
    "external_aad": "",
    "expect": "decrypt",
}

# --- V8: nested recipients: EncMessage -> KeyWrap -> DirectEncryption ---
inner = DirectEncryption(uhdr={"ALG": "DIRECT"})
outer = KeyWrap(uhdr={"ALG": "A128KW"})
outer.key = SymmetricKey(k=KEK, optional_params={KpAlg: "A128KW", KpKeyOps: [WrapOp, UnwrapOp]})
outer.payload = CEK
outer.recipients = [inner]
msg = EncMessage(phdr={"ALG": "A128GCM"}, uhdr={"IV": IV}, payload=PAYLOAD, recipients=[outer])
msg.key = sym_key("A128GCM", [EncryptOp, DecryptOp])
vectors["enc_nested_recipient"] = {
    "cbor": msg.encode().hex(),
    "payload": PAYLOAD.hex(),
    "external_aad": "",
    "expect": "decrypt",
}

# --- V9: Mac0 HMAC ---
msg = Mac0Message(phdr={"ALG": "HMAC_256_64"}, payload=PAYLOAD, external_aad=AAD)
msg.key = sym_key("HMAC_256_64", [MacCreateOp, MacVerifyOp])
vectors["mac0_hmac"] = {
    "cbor": msg.encode().hex(),
    "payload": PAYLOAD.hex(),
    "external_aad": AAD.hex(),
    "expect": "verify",
}

# --- V10: COSE_Mac with direct recipient ---
rcpt = DirectEncryption(uhdr={"ALG": "DIRECT", "KID": b"our-secret"})
msg = MacMessage(phdr={"ALG": "HMAC_256_64"}, uhdr={}, payload=PAYLOAD, recipients=[rcpt])
msg.key = sym_key("HMAC_256_64", [MacCreateOp, MacVerifyOp])
vectors["mac_direct"] = {
    "cbor": msg.encode().hex(),
    "payload": PAYLOAD.hex(),
    "external_aad": "",
    "expect": "verify",
}

# --- V11: COSE key CBOR round-trip ---
key = ec_pub()
key.key_ops = [VerifyOp]
vectors["cose_key"] = {"cbor": key.encode().hex(), "expect": "key"}

# --- negative vectors (hand-crafted) ---
vectors["neg_not_tagged"] = {"cbor": cbor2.dumps([b"", {}, b"x"]).hex(), "expect": "error:AttributeError"}
vectors["neg_unknown_tag"] = {"cbor": cbor2.dumps(cbor2.CBORTag(9999, [b"", {}, b"x", b"y"])).hex(), "expect": "error:KeyError"}
vectors["neg_tag_not_array"] = {"cbor": cbor2.dumps(cbor2.CBORTag(18, {1: 2})).hex(), "expect": "error:TypeError"}
vectors["neg_sign1_phdr_not_bstr"] = {"cbor": cbor2.dumps(cbor2.CBORTag(18, [{1: -7}, {}, b"p", b"s"])).hex(), "expect": "error"}
vectors["neg_sign1_uhdr_not_map"] = {"cbor": cbor2.dumps(cbor2.CBORTag(18, [b"", [1, 2], b"p", b"s"])).hex(), "expect": "error"}
vectors["enc_empty_recipients"] = {
    "cbor": cbor2.dumps(cbor2.CBORTag(96, [b"", {}, b"ct", []])).hex(), "expect": "accept_lenient"}
vectors["neg_truncated"] = {"cbor": vectors["sign1_es256"]["cbor"][:20], "expect": "error"}
vectors["neg_direct_with_nested"] = {
    "cbor": cbor2.dumps(cbor2.CBORTag(96, [b"", {}, b"ct", [[b"", {1: -6}, b"", [[b"", {}, b""]]]]])).hex(),
    "expect": "error:CoseMalformedMessage"}

out = os.path.join(os.path.dirname(__file__), "migration-vectors.json")
with open(out, "w") as f:
    json.dump(vectors, f, indent=1)
print("wrote", out, len(vectors), "vectors")
