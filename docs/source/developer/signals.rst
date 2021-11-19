=======
Signals
=======

``radius_accounting_success``
-----------------------------

**Path**: ``openwisp_radius.signals.radius_accounting_success``

**Arguments**:

- ``sender`` : instance of ``AccountingView``
- ``accounting_data`` (``dict``): accounting information

This signal is emitted every time the accounting REST API endpoint
completes successfully, just before the response is returned.
