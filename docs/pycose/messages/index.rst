COSE Messages
=============

.. toctree::
   :maxdepth: 1

   sign1message.rst
   signmessage.rst
   macmessage.rst
   mac0message.rst
   encmessage.rst
   enc0message.rst

Modifying message headers
-------------------------

The protected header of a COSE message is cryptographically authenticated: the
signature, authentication tag or ciphertext is computed over the encoded protected
header bytes (``phdr_encoded``). To guarantee that the header attributes observed by
an application always correspond to the bytes used by the cryptographic operations,
the header buckets of a message are exposed as **read-only views**.

This means that direct, in-place modification of a decoded message is **not
supported** and raises an error::

    >>> from pycose.messages import Sign1Message
    >>> msg = Sign1Message(phdr={'ALG': 'EdDSA'}, payload=b'data')
    >>> msg.phdr['ALG'] = 'ES256'
    Traceback (most recent call last):
    ...
    TypeError: '_FrozenHeaderDict' object does not support item assignment

The same applies to nested mutable values (e.g. appending to a list-valued header
attribute) and to values returned by
:func:`~pycose.messages.cosebase.CoseBase.get_attr`.

Headers can only be changed through the controlled update paths:

* assigning a new dict to the ``phdr``/``uhdr`` properties, or
* calling ``phdr_update()``/``uhdr_update()`` with the parameters to change.

Both paths invalidate the cached encoded protected header, so the next
``phdr_encoded`` access (and hence the next signature, tag or encryption
operation) re-encodes the header from the currently visible attributes. Messages
that were decoded and never modified keep their original encoded protected header
bytes, so re-encoding them yields the identical message.

