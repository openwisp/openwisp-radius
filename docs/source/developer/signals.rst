=======
Signals
=======

``radius_accounting_success``
-----------------------------

**Path**: ``openwisp_radius.signals.radius_accounting_success``

**Arguments**:

- ``sender`` (``str``): the view that sends the signal
- ``accounting_data`` (``dict``): accounting information

This signal is emitted every time the accounting REST API endpoint
completes successfully, just before the response is returned.
