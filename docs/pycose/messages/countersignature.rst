Countersignatures
=================

RFC 9338 defines version 2 countersignatures, carried by the CounterSignatureV2 (11) and
CounterSignature0V2 (12) header parameters. A countersignature can be attached to COSE_Sign1,
COSE_Sign, COSE_Signature, COSE_Encrypt, COSE_Encrypt0, COSE_Mac, COSE_Mac0 and COSE_Recipient
objects.

The countersignature is computed over a Countersign_structure built from the fields of the
countersigned object (its protected header, external AAD, payload and, for signed messages, the
signature values in other_fields).

.. module:: pycose.messages.countersignature

.. autoclass:: Countersignature
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag

.. autoclass:: Countersignature0
    :members:
    :inherited-members:
    :exclude-members: from_cose_obj, record_cbor_tag

.. autofunction:: create_countersign_structure

