class CoseIllegalAlgorithm(Exception):
    pass


class CoseUnsupportedCurve(Exception):
    pass


class CoseIllegalKeyOps(Exception):
    pass


class CoseIllegalKeyType(Exception):
    pass


class CoseMalformedMessage(Exception):
    pass


class CoseInvalidKey(Exception):
    pass


class CoseException(Exception):
    pass


class CoseNoUsableKey(CoseException):
    """ Raised when none of the keys in a key set can recover the content encryption key. """
    pass


class CoseContentAuthenticationFailed(CoseException):
    """ Raised when a decryption path was found but AEAD verification of the content failed. """
    pass
