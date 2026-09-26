import os
from typing import List, NamedTuple, Optional, Tuple, TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from pycose import utils, headers
from pycose.exceptions import CoseException, CoseMalformedMessage, CoseNoMatchingKey
from pycose.keys.cosekey import CoseKey
from pycose.keys.ec2 import EC2Key
from pycose.keys.keyops import EncryptOp, DecryptOp, UnwrapOp, DeriveKeyOp, DeriveBitsOp
from pycose.keys.keyparam import KpAlg, KpKeyOps
from pycose.keys.okp import OKPKey
from pycose.keys.rsa import RSAKey
from pycose.keys.symmetric import SymmetricKey
from pycose.algorithms import RsaesOaepSha1, RsaesOaepSha256, RsaesOaepSha512
from pycose.messages import enccommon, cosemessage
from pycose.messages.recipient import DirectEncryption, DirectKeyAgreement, KeyWrap, KeyAgreementWithKeyWrap, \
    CoseRecipient

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK
    from pycose.messages.recipient import Recipient

CBOR = bytes

# crypto errors signaling that a candidate key simply does not fit (safe to try the next key)
_KEY_MISMATCH_ERRORS = (InvalidUnwrap, ValueError)

# key operations a candidate key must support per recipient class
_RECIPIENT_KEY_OPS = {
    DirectEncryption: (DecryptOp,),
    DirectKeyAgreement: (DeriveKeyOp, DeriveBitsOp),
    KeyWrap: (UnwrapOp, DecryptOp),
    KeyAgreementWithKeyWrap: (DeriveKeyOp, DeriveBitsOp),
}


class KeySetDecryptionResult(NamedTuple):
    """ Result of a successful decrypt_with_key_set call on an EncMessage. """

    plaintext: bytes
    recipient_path: List['Recipient']
    key: CoseKey

    @property
    def kid(self) -> bytes:
        """ The key identifier of the COSE key that was used to decrypt the message. """

        return self.key.kid


def _matches_recipient(key: CoseKey, recipient: 'Recipient') -> bool:
    """
    Check if a candidate COSE key is compatible with a COSE recipient structure based on the key type, the
    algorithm, the key identifier, the curve and the key operations.
    """

    alg = recipient.get_attr(headers.Algorithm)
    if alg is None:
        raise CoseMalformedMessage(f"COSE recipient {recipient} does not carry an algorithm header parameter")

    # check key type compatibility
    if isinstance(recipient, (DirectKeyAgreement, KeyAgreementWithKeyWrap)):
        if not isinstance(key, (EC2Key, OKPKey)):
            return False
    elif isinstance(recipient, KeyWrap) and alg in {RsaesOaepSha1, RsaesOaepSha256, RsaesOaepSha512}:
        if not isinstance(key, RSAKey):
            return False
    elif not isinstance(key, SymmetricKey):
        return False

    # check for conflicting algorithms in the key and the recipient structure
    if key.alg is not None and key.alg != alg:
        return False

    # check the key identifier
    kid = recipient.get_attr(headers.KID)
    if kid is not None and key.kid != b'' and key.kid != kid:
        return False

    # check the curve against the public key of the sender
    if isinstance(recipient, (DirectKeyAgreement, KeyAgreementWithKeyWrap)):
        peer_key = recipient.get_attr(headers.EphemeralKey)
        if peer_key is None:
            peer_key = recipient.get_attr(headers.StaticKey)
        if peer_key is not None and getattr(peer_key, 'crv', None) is not None and peer_key.crv != key.crv:
            return False

    # check the key operations
    required_ops = next(ops for rcpt_type, ops in _RECIPIENT_KEY_OPS.items() if isinstance(recipient, rcpt_type))
    if len(key.key_ops) and not any(op in key.key_ops for op in required_ops):
        return False

    return True


def _unwrap_recipient(recipient: 'Recipient',
                      target_alg,
                      keys: List[CoseKey],
                      path: List['Recipient']) -> Optional[Tuple[bytes, CoseKey]]:
    """
    Attempt to recover the key bytes protected by a key wrap/key agreement recipient structure, following
    nested recipient structures if required.

    :returns: The recovered key bytes and the COSE key that recovered them, or None if no key matched.
    """

    if isinstance(recipient, DirectKeyAgreement):
        for key in keys:
            if not _matches_recipient(key, recipient):
                continue
            recipient.key = key
            try:
                derived_key = recipient.compute_cek(target_alg, "decrypt")
            except _KEY_MISMATCH_ERRORS:
                continue
            path.append(recipient)
            return derived_key.k, key
        return None

    for key in keys:
        if not _matches_recipient(key, recipient):
            continue
        recipient.key = key
        try:
            cek_bytes = recipient.decrypt(target_alg)
        except _KEY_MISMATCH_ERRORS:
            continue
        path.append(recipient)
        return cek_bytes, key

    if isinstance(recipient, KeyWrap):
        # no candidate key unwraps this layer directly, derive the KEK from a nested recipient structure
        wrap_alg = recipient.get_attr(headers.Algorithm)
        for nested in recipient.recipients:
            recovered = _unwrap_recipient(nested, wrap_alg, keys, path)
            if recovered is None:
                continue
            kek_bytes, key = recovered
            recipient.key = SymmetricKey(k=kek_bytes,
                                         optional_params={KpAlg: wrap_alg, KpKeyOps: [UnwrapOp, DecryptOp]})
            cek_bytes = recipient.decrypt(target_alg)
            path.append(recipient)
            return cek_bytes, key

    return None


@cosemessage.CoseMessage.record_cbor_tag(96)
class EncMessage(enccommon.EncCommon):
    context = "Encrypt"
    cbor_tag = 96

    @classmethod
    def from_cose_obj(cls, cose_obj: list, allow_unknown_attributes: bool) -> 'EncMessage':
        msg = super().from_cose_obj(cose_obj, allow_unknown_attributes)

        try:
            msg.recipients = [CoseRecipient.create_recipient(r, allow_unknown_attributes, context='Enc_Recipient') for r
                              in cose_obj.pop(0)]
        except (IndexError, ValueError):
            msg.recipients = []
        return msg

    def __init__(self,
                 phdr: Optional[dict] = None,
                 uhdr: Optional[dict] = None,
                 payload: bytes = b'',
                 external_aad: bytes = b'',
                 key: Optional['SK'] = None,
                 recipients: Optional[List['Recipient']] = None,
                 *args,
                 **kwargs):
        """
        Create a COSE_Encrypt message.

        :param phdr: Protected header.
        :param uhdr: Unprotected header.
        :param payload: The payload of the COSE_Encrypt message.
        :param external_aad: External additional data (is authenticated by not included in the final message)
        :param recipients: An optional list of :class:`~pycose.messages.recipient.CoseRecipient` objects.
        """

        super().__init__(phdr, uhdr, payload, external_aad, key, *args, **kwargs)

        self._recipients = []
        self.recipients = recipients

    def encode(self, tag: bool = True, encrypt: bool = True, *args, **kwargs) -> CBOR:
        """ Encodes and protects the COSE_Encrypt message """

        # encode/wrap_cek the base fields
        if encrypt:
            message = [self.phdr_encoded, self.uhdr_encoded, self.encrypt()]
        else:
            message = [self.phdr_encoded, self.uhdr_encoded, self.payload]

        if len(self.recipients):
            message.append([r.encode(target_alg=self.get_attr(headers.Algorithm)) for r in self.recipients])

        res = super(EncMessage, self).encode(message, tag)
        return res

    def encrypt(self, *args, **kwargs) -> bytes:
        target_algorithm = self.get_attr(headers.Algorithm)

        r_types = CoseRecipient.verify_recipients(self.recipients)

        if DirectEncryption in r_types:
            # key should already be known
            payload = super(EncMessage, self).encrypt()

        elif DirectKeyAgreement in r_types:
            self.key = self.recipients[0].compute_cek(target_algorithm, "encrypt")
            payload = super(EncMessage, self).encrypt()

        elif KeyWrap in r_types or KeyAgreementWithKeyWrap in r_types:
            key_bytes = os.urandom(self.get_attr(headers.Algorithm).get_key_length())
            for r in self.recipients:
                if r.payload == b'':
                    r.payload = key_bytes
                else:
                    key_bytes = r.payload
                r.encrypt(target_algorithm)
            self.key = SymmetricKey(k=key_bytes, optional_params={KpAlg: target_algorithm, KpKeyOps: [EncryptOp]})
            payload = super(EncMessage, self).encrypt()

        else:
            raise CoseException('Unsupported COSE recipient class')

        return payload

    def decrypt(self, recipient: 'Recipient', *args, **kwargs) -> bytes:
        target_algorithm = self.get_attr(headers.Algorithm)

        # check if recipient exists
        if not CoseRecipient.has_recipient(recipient, self.recipients):
            raise CoseException(f"Cannot find recipient: {recipient}")

        r_types = CoseRecipient.verify_recipients(self.recipients)

        if DirectEncryption in r_types:
            # key should already be known
            payload = super(EncMessage, self).decrypt()

        elif DirectKeyAgreement in r_types or KeyWrap in r_types or KeyAgreementWithKeyWrap in r_types:
            self.key = recipient.compute_cek(target_algorithm, "decrypt")
            payload = super(EncMessage, self).decrypt()
        else:
            raise CoseException('Unsupported COSE recipient class')

        return payload

    def decrypt_with_key_set(self, keys: List[CoseKey]) -> KeySetDecryptionResult:
        """
        Attempt to decrypt the COSE_Encrypt message with a set of candidate COSE keys, without requiring
        prior knowledge of where a key fits in the (nested) recipient structure.

        Candidate keys are filtered per recipient structure based on the key identifier, the algorithm, the
        curve and the key operations. Nested key wrap/key agreement structures are followed to recover the
        CEK. A candidate key that does not unwrap a layer is skipped, but malformed recipient structures,
        conflicting protected/unprotected header attributes and illegal algorithm combinations are raised
        to the caller. A recovered CEK is always verified against the content AEAD algorithm.

        :param keys: A list of candidate CoseKey objects.

        :raises CoseNoMatchingKey: When none of the provided keys can decrypt the message.
        :raises cryptography.exceptions.InvalidTag: When a decryption path was found but the content
            authentication failed.
        :returns: A KeySetDecryptionResult holding the plaintext, the successful recipient path and the
            COSE key that was used.
        """

        if not len(self.recipients):
            raise CoseMalformedMessage("COSE_Encrypt message does not carry any recipients")

        target_algorithm = self.get_attr(headers.Algorithm)
        if target_algorithm is None:
            raise CoseMalformedMessage("COSE_Encrypt message does not carry a content encryption algorithm")

        # structural sanity checks on the recipient configuration
        CoseRecipient.verify_recipients(self.recipients)

        keys = list(keys)
        for key in keys:
            if not isinstance(key, CoseKey):
                raise TypeError(f"Keys must be of type {CoseKey}")

        for recipient in self.recipients:
            if isinstance(recipient, DirectEncryption):
                for key in keys:
                    if not _matches_recipient(key, recipient):
                        continue
                    self.key = key
                    try:
                        plaintext = super(EncMessage, self).decrypt()
                    except InvalidTag:
                        continue
                    return KeySetDecryptionResult(plaintext, [recipient], key)

            elif isinstance(recipient, DirectKeyAgreement):
                for key in keys:
                    if not _matches_recipient(key, recipient):
                        continue
                    recipient.key = key
                    try:
                        self.key = recipient.compute_cek(target_algorithm, "decrypt")
                    except _KEY_MISMATCH_ERRORS:
                        continue
                    try:
                        plaintext = super(EncMessage, self).decrypt()
                    except InvalidTag:
                        continue
                    return KeySetDecryptionResult(plaintext, [recipient], key)

            elif isinstance(recipient, (KeyWrap, KeyAgreementWithKeyWrap)):
                path = []
                recovered = _unwrap_recipient(recipient, target_algorithm, keys, path)
                if recovered is None:
                    continue
                cek_bytes, key = recovered
                self.key = SymmetricKey(k=cek_bytes,
                                        optional_params={KpAlg: target_algorithm, KpKeyOps: [DecryptOp]})
                # the recovered CEK still has to authenticate the content
                plaintext = super(EncMessage, self).decrypt()
                path.reverse()
                return KeySetDecryptionResult(plaintext, path, key)

            else:
                raise CoseException(f'Unsupported COSE recipient class: {type(recipient)}')

        raise CoseNoMatchingKey("None of the provided COSE keys can decrypt the COSE_Encrypt message")

    @property
    def recipients(self) -> List['Recipient']:
        return self._recipients

    @recipients.setter
    def recipients(self, recipients: List['Recipient']) -> None:

        if recipients is None:
            self._recipients = []
        else:
            for r in recipients:
                if not issubclass(type(r), CoseRecipient):
                    raise TypeError(f"Recipient must be a subclass of {CoseRecipient}")
                self._recipients.append(r)

    def __repr__(self) -> str:
        phdr, uhdr = self._hdr_repr()
        rcpts = str(self.recipients)

        return f'<COSE_Encrypt: [{phdr}, {uhdr}, {utils.truncate(self._payload)}, {rcpts}]>'
