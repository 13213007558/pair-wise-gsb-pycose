import os
from typing import Iterable, List, NamedTuple, Optional, Tuple, TYPE_CHECKING, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

from pycose import utils, headers
from pycose.algorithms import A128KW, A192KW, A256KW, RsaesOaepSha1, RsaesOaepSha256, RsaesOaepSha512, \
    EcdhEsHKDF256, EcdhEsHKDF512, EcdhEsA128KW, EcdhEsA192KW, EcdhEsA256KW, EcdhSsHKDF256, EcdhSsHKDF512, \
    EcdhSsA128KW, EcdhSsA192KW, EcdhSsA256KW, Direct
from pycose.exceptions import CoseException, CoseMalformedMessage, CoseIllegalAlgorithm, CoseNoUsableKey, \
    CoseContentAuthenticationFailed
from pycose.keys.cosekey import CoseKey
from pycose.keys.ec2 import EC2Key
from pycose.keys.keyops import EncryptOp, DecryptOp, UnwrapOp, DeriveKeyOp, DeriveBitsOp
from pycose.keys.keyparam import KpAlg, KpKeyOps
from pycose.keys.rsa import RSAKey
from pycose.keys.symmetric import SymmetricKey
from pycose.messages import enccommon, cosemessage
from pycose.messages.recipient import DirectEncryption, DirectKeyAgreement, KeyWrap, KeyAgreementWithKeyWrap, \
    CoseRecipient

if TYPE_CHECKING:
    from pycose.keys.symmetric import SK
    from pycose.messages.recipient import Recipient

CBOR = bytes


_AES_KW_ALGS = {A128KW, A192KW, A256KW}
_RSA_KW_ALGS = {RsaesOaepSha1, RsaesOaepSha256, RsaesOaepSha512}
_ECDH_ES_ALGS = {EcdhEsHKDF256, EcdhEsHKDF512, EcdhEsA128KW, EcdhEsA192KW, EcdhEsA256KW}
_ECDH_SS_ALGS = {EcdhSsHKDF256, EcdhSsHKDF512, EcdhSsA128KW, EcdhSsA192KW, EcdhSsA256KW}


class KeySetDecryptionResult(NamedTuple):
    """
    Result of a successful key-set decryption of a COSE_Encrypt message.

    :ivar plaintext: The decrypted and authenticated plaintext.
    :ivar recipients: The recipient path (from the top-level recipient down to the recipient the key was \
    applied to) that led to the recovered content encryption key.
    :ivar kid: The key identifier of the COSE key that was used, or None if the key carries no kid.
    """

    plaintext: bytes
    recipients: Tuple['CoseRecipient', ...]
    kid: Optional[bytes]


def _recipient_paths(recipients: List['CoseRecipient'], prefix: tuple = ()) -> Iterable[Tuple['CoseRecipient', ...]]:
    """ Yield all recipient paths in the (nested) recipient tree, parents before children. """

    for r in recipients:
        path = prefix + (r,)
        yield path
        yield from _recipient_paths(r.recipients, path)


def _has_key_ops(key: 'CoseKey', allowed: set) -> bool:
    """ Keys without an explicit key_ops parameter are considered unrestricted. """

    return not len(key.key_ops) or any(op in key.key_ops for op in allowed)


def _key_matches_recipient(recipient: 'CoseRecipient', key: 'CoseKey', target_alg) -> bool:
    """
    Check whether a COSE key is a candidate for the given recipient structure, based on the key identifier, the
    algorithm, the curve and the key operations. Structural problems in the recipient (conflicting header buckets,
    missing key material, illegal algorithms) are raised instead of reported as a non-match.
    """

    alg = recipient.get_attr(headers.Algorithm)
    if alg is None:
        raise CoseMalformedMessage("COSE recipient structure without an algorithm parameter")

    kid = recipient.get_attr(headers.KID)
    if kid is not None and key.kid != kid:
        return False

    if isinstance(recipient, DirectEncryption):
        if alg != Direct:
            raise CoseIllegalAlgorithm(f"Algorithm {alg} unsupported for {DirectEncryption.__name__}")
        if not isinstance(key, SymmetricKey):
            return False
        # for direct encryption the key encrypts the content itself, so it must match the content algorithm
        if key.alg is not None and key.alg.identifier != target_alg.identifier:
            return False
        return _has_key_ops(key, {DecryptOp})

    if key.alg is not None and key.alg.identifier != alg.identifier:
        return False

    if alg in _AES_KW_ALGS:
        if not isinstance(key, SymmetricKey):
            return False
        return _has_key_ops(key, {UnwrapOp, DecryptOp})

    if alg in _RSA_KW_ALGS:
        if not isinstance(key, RSAKey):
            return False
        return _has_key_ops(key, {UnwrapOp, DecryptOp})

    if alg in _ECDH_ES_ALGS or alg in _ECDH_SS_ALGS:
        if not isinstance(key, EC2Key):
            return False
        if not _has_key_ops(key, {DeriveKeyOp, DeriveBitsOp}):
            return False
        peer_key = recipient.get_attr(headers.EphemeralKey if alg in _ECDH_ES_ALGS else headers.StaticKey)
        if peer_key is None:
            raise CoseMalformedMessage(f"COSE recipient with algorithm {alg} must carry a peer key in its headers")
        return key.crv == peer_key.crv

    raise CoseIllegalAlgorithm(f"Unsupported recipient algorithm {alg} for key-set decryption")


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

    def decrypt_with_key_set(self, keys: Union['CoseKey', Iterable['CoseKey']]) -> 'KeySetDecryptionResult':
        """
        Try to decrypt the COSE_Encrypt message with a set of COSE keys, without knowing in advance which key
        belongs to which (possibly nested) recipient structure.

        Candidate keys are selected per recipient based on the key identifier, algorithm, curve and key
        operations. The content encryption key is then recovered by following the nested key-wrap/key-agreement
        relations, and the content is decrypted and authenticated (AEAD) before it is returned.

        A candidate key that simply does not fit (e.g. wrong key bytes) is skipped in favor of the next
        candidate. Structural errors in the message, conflicting protected/unprotected header parameters and
        illegal algorithm combinations are raised and never silently treated as a non-matching key.

        :param keys: A single COSE key or an iterable of COSE keys to try.

        :raises CoseNoUsableKey: When no key in the key set could recover the content encryption key.
        :raises CoseContentAuthenticationFailed: When a decryption path was found but the AEAD verification of \
        the content failed.
        :raises CoseMalformedMessage: When the message or a recipient structure is malformed.
        :raises CoseIllegalAlgorithm: When a recipient uses an illegal or unsupported algorithm.
        :raises CoseException: When conflicting header parameters are found in the protected and unprotected \
        header buckets.
        :returns: A :class:`KeySetDecryptionResult` with the plaintext, the recipient path and the key identifier.
        """

        if isinstance(keys, CoseKey):
            keys = [keys]
        else:
            keys = list(keys)

        target_alg = self.get_attr(headers.Algorithm)
        if target_alg is None:
            raise CoseMalformedMessage("COSE_Encrypt message without an algorithm parameter")

        CoseRecipient.verify_recipients(self.recipients)

        for path in _recipient_paths(self.recipients):
            recipient = path[-1]
            for key in keys:
                if not _key_matches_recipient(recipient, key, target_alg):
                    continue

                original_keys = [r.key for r in path]
                original_msg_key = self.key
                try:
                    cek = self._recover_cek(path, key, target_alg)
                except (InvalidUnwrap, ValueError):
                    # key material does not fit the wrapped key(s): try the next candidate
                    continue
                finally:
                    for r, original_key in zip(path, original_keys):
                        r.key = original_key

                self.key = cek
                try:
                    plaintext = super().decrypt()
                except InvalidTag as e:
                    self.key = original_msg_key
                    raise CoseContentAuthenticationFailed(
                        "Recovered a content encryption key but AEAD verification of the content failed") from e

                return KeySetDecryptionResult(plaintext=plaintext, recipients=path, kid=key.kid or None)

        raise CoseNoUsableKey("None of the keys in the key set could recover the content encryption key")

    def _recover_cek(self, path: Tuple['CoseRecipient', ...], key: 'CoseKey', target_alg) -> 'SymmetricKey':
        """
        Recover the content encryption key by applying the candidate key at the last recipient of the path and
        unwrapping the key hierarchy up to the top-level recipient.
        """

        recipient = path[-1]
        recipient.key = key

        if isinstance(recipient, DirectEncryption):
            # alg is Direct: the key itself is the content encryption key
            return SymmetricKey(k=recipient.key.k, optional_params={KpAlg: target_alg, KpKeyOps: [DecryptOp]})

        if isinstance(recipient, DirectKeyAgreement):
            return recipient.compute_cek(target_alg, "decrypt")

        key_bytes = recipient.decrypt(target_alg)

        for ancestor in reversed(path[:-1]):
            if not isinstance(ancestor, KeyWrap):
                raise CoseMalformedMessage(
                    f"Recipient of type {type(ancestor).__name__} cannot unwrap a key delivered by its recipients")
            ancestor.key = SymmetricKey(k=key_bytes)
            key_bytes = ancestor.decrypt(target_alg)

        return SymmetricKey(k=key_bytes, optional_params={KpAlg: target_alg, KpKeyOps: [DecryptOp]})

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
