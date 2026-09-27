Countersignature
================

.. module:: pycose.messages.countersignature

The CoseCounterSignature and CoseCounterSignature0 structures implement the RFC 9338
countersignatures (CounterSignatureV2 and CounterSignature0V2). They are carried in the
unprotected header bucket of COSE messages, signers or recipient structures under the
CounterSignatureV2 and CounterSignature0V2 header attributes.

When a countersignature object with a key is attached to a message, the signature is computed
automatically during encoding. Received countersignatures are parsed automatically and can be
verified with the verify_countersignature method of the countersigned object.

.. autoclass:: CoseCounterSignature
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj

.. autoclass:: CoseCounterSignature0
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj

