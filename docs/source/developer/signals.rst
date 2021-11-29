=======
Signals
=======

``radius_accounting_success``
-----------------------------

**Path**: ``openwisp_radius.signals.radius_accounting_success``

**Arguments**:

- ``sender`` : ``AccountingView``
- ``accounting_data`` (``dict``): accounting information
- ``view``: instance of ``AccountingView``

This signal is emitted every time the accounting REST API endpoint
completes successfully, just before the response is returned.

The ``view`` argument can also be used to access the ``request``
object i.e. ``view.request``.
