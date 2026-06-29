Management commands
===================

These management commands are necessary for enabling certain features and
for database cleanup.

Example usage:

.. code-block:: shell

    cd tests/
    ./manage.py <command> <args>

In this page we list the management commands currently available in
**openwisp-radius**.

``delete_old_radacct``
----------------------

This command deletes RADIUS accounting sessions older than ``<days>``.

.. code-block:: shell

    ./manage.py delete_old_radacct <days>

For example:

.. code-block:: shell

    ./manage.py delete_old_radacct 365

``delete_old_postauth``
-----------------------

This command deletes RADIUS post-auth logs older than ``<days>``.

.. code-block:: shell

    ./manage.py delete_old_postauth <days>

For example:

.. code-block:: shell

    ./manage.py delete_old_postauth 365

``cleanup_stale_radacct``
-------------------------

This command closes stale RADIUS sessions that have remained open for the
number of specified ``<days>``.

.. code-block:: shell

    ./manage.py cleanup_stale_radacct <days>

For example:

.. code-block:: shell

    ./manage.py cleanup_stale_radacct 15

If you need to clean up stale sessions more aggressively, you can use
hours instead of days:

.. code-block:: shell

    ./manage.py cleanup_stale_radacct --number_of_hours=4

``delete_old_radiusbatch_users``
--------------------------------

This command deletes users created using batch operation that have expired
for more than the specified ``<duration_in_days>``.

.. code-block:: shell

    ./manage.py delete_old_radiusbatch_users --older-than-days <duration_in_days>

Note that the default duration is set to **540 days** (18 months).

For backward compatibility, the command also accepts the argument
``--older-than-months``:

.. code-block:: shell

    ./manage.py delete_old_radiusbatch_users --older-than-months <duration_in_months>

If both ``--older-than-days`` and ``--older-than-months`` are provided,
preference is given to ``--older-than-days``.

``delete_unverified_users``
---------------------------

This command deletes unverified users that have been registered for more
than specified duration and have no associated radius session. This
feature is needed to delete users who have registered but never completed
the verification process. **Staff users will not be deleted by this
management command.**

.. code-block:: shell

    ./manage.py delete_unverified_users --older-than-days <duration_in_days>

Note that the default duration is set to **1 day**.

It is also possible to exclude users that have registered using specified
methods. You can specify multiple methods separated by comma(`,`).
Following is an example:

.. code-block:: shell

    ./manage.py delete_unverified_users --older-than-days 1 --exclude-methods mobile_phone,email

If a user has multiple ``RegisteredUser`` rows across organizations, the
command keeps that user when **any** related row uses one of the excluded
methods.

.. _radius_convert_called_station_id:

``convert_called_station_id``
-----------------------------

If an installation uses a centralized captive portal, the value of "Called
Station ID" of RADIUS Sessions will always show the MAC address of the
captive portal instead of the access points.

This command will update the "Called Station ID" to reflect the MAC
address of the access points using information from OpenVPN. It requires
installing ``openvpn_status``, which can be installed using the following
command

.. code-block:: shell

    pip install openwisp-radius[openvpn_status]

In order to work, this command requires to be configured via the
:ref:`OPENWISP_RADIUS_CALLED_STATION_IDS
<openwisp_radius_called_station_ids>` setting.

Use the following command if you want to perform this operation for all
RADIUS sessions that meet criteria of
``OPENWISP_RADIUS_CALLED_STATION_IDS`` setting.

.. code-block:: shell

    ./manage.py convert_called_station_id

You can also convert the "Called Station ID" of a particular RADIUS
session by replacing session's ``unique_id`` in the following command:

.. code-block:: shell

    ./manage.py convert_called_station_id --unique_id=<session_unique_id>

.. note::

    If you encounter ``ParseError`` for datetime data, you can set the
    datetime format of the parser using
    :ref:`OPENWISP_RADIUS_OPENVPN_DATETIME_FORMAT
    <openwisp_radius_openvpn_datetime_format>` setting.

.. note::

    ``convert_called_station_id`` command will only operate on open RADIUS
    sessions, i.e. the "stop_time" field is None.

    But if you are converting a single RADIUS session, it will operate on
    it even if the session is closed.
