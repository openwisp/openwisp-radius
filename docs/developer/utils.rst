Code Utilities
==============

.. include:: ../partials/developer-docs.rst

.. contents:: **Table of Contents**:
    :depth: 2
    :local:

Signals
-------

``radius_accounting_success``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Path**: ``openwisp_radius.signals.radius_accounting_success``

**Arguments**:

- ``sender`` : ``AccountingView``
- ``accounting_data`` (``dict``): accounting information
- ``view``: instance of ``AccountingView``

This signal is emitted every time the accounting REST API endpoint
completes successfully, just before the response is returned.

The ``view`` argument can also be used to access the ``request`` object
i.e. ``view.request``.

``radius_accounting_closed``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Path**: ``openwisp_radius.signals.radius_accounting_closed``

**Arguments**:

- ``sender``: ``RadiusAccounting`` model class
- ``instance``: closed ``RadiusAccounting`` instance

This signal is emitted when a ``RadiusAccounting`` session is closed. For
regular ``save()`` paths, it is emitted only when ``stop_time`` changes
from ``None`` to any value, or when a closed session is created directly.
Editing an already closed session does not emit this signal again.

Integrations which need to react to closed accounting sessions should
listen to this signal. For example, the monitoring integration uses this
signal to write RADIUS traffic snapshots for sessions closed by regular
``post_save`` paths, ``Accounting-On`` packets and automatic stale-session
cleanup.

When closing multiple sessions with ``bulk_update()``, use
``openwisp_radius.utils.emit_radius_accounting_closed`` after the database
update to emit this signal once for each closed session.

.. _radius_captive_portal_mock_views:

Captive portal mock views
-------------------------

The development environment of openwisp-radius provides two URLs that mock
the behavior of a captive portal, these URLs can be used when testing
frontend applications like :doc:`OpenWISP WiFi Login Pages
</wifi-login-pages/index>` during development.

.. note::

    These views are meant to be used just for development and testing.

Captive Portal Login Mock View
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **URL**: ``http://localhost:8000/captive-portal-mock/login/``.
- **POST fields**: ``auth_pass`` or ``password``.

This view handles the captive portal login process by first checking for
either an ``auth_pass`` or ``password`` in the POST request data. It then
attempts to find a corresponding ``RadiusToken`` instance where the key
matches the provided value. If a matching token is found and there are no
active sessions (i.e., no open ``RadiusAccounting`` records), then it
creates a new radius session for the user. If successful, the user is
considered logged in.

Captive Portal Logout Mock View
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- **URL**: ``http://localhost:8000/captive-portal-mock/logout/``.
- **POST fields**: ``logout_id``.

This view looks for an entry in the ``radacct`` table where ``session_id``
matches the value passed in the ``logout_id`` POST field. If such an entry
is found, the view makes a ``POST`` request to the accounting view to mark
the session as terminated, using ``User-Request`` as the termination
cause.
