===================
Management commands
===================

These management commands are necessary for enabling certain features and
for database cleanup.

Example usage:

.. code-block:: shell

    cd tests/
    ./manage.py <command> <args>

In this page we list the management commands currently available in **openwisp-radius**.

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

This command closes stale RADIUS sessions that have remained open for
the number of specified ``<days>``.

.. code-block:: shell

    ./manage.py cleanup_stale_radacct <days>

For example:

.. code-block:: shell

    ./manage.py cleanup_stale_radacct 15

``deactivate_expired_users``
----------------------------

.. note::
  `Find out more about this feature in its dedicated page <./generating_users.html>`_

This command deactivates expired user accounts which were created temporarily
(eg: for en event) and have an expiration date set.

.. code-block:: shell

    ./manage.py deactivate_expired_users

``delete_old_users``
--------------------

This command deletes users that have expired (and should have been deactivated by
``deactivate_expired_users``) for more than the specified ``<duration_in_months>``.

.. code-block:: shell

    ./manage.py delete_old_users --older-than-months <duration_in_months>

Note that the default duration is set to 18 months.

``delete_unverified_users``
---------------------------

This command deletes unverified users that have been registered for
more than specified duration and have no associated radius session.
This feature is needed to delete users who have registered but never
completed the verification process.
**Staff users will not be deleted by this management command.**

.. code-block:: shell

    ./manage.py delete_unverified_users --older-than-days <duration_in_days>

Note that the default duration is set to 1 day.

It is also possible to exclude users that have registered using specified methods.
You can specify multiple methods separated by comma(`,`). Following is an example:

.. code-block:: shell

    ./manage.py delete_unverified_users --older-than-days 1 --exclude-methods mobile_phone,email

``upgrade_from_django_freeradius``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you are upgrading from `django-freeradius <https://github.com/openwisp/django-freeradius>`_
to openwisp-radius, there is an easy migration script that will import your freeradius
database, sites, social website account users, users & groups to openwisp-radius instance::

    ./manage.py upgrade_from_django_freeradius

The management command accepts an argument ``--backup``, that you can pass
to give the location of the backup files, by default it looks in the ``tests/``
directory, eg::

    ./manage.py upgrade_from_django_freeradius --backup /home/user/django_freeradius/

The management command accepts another argument ``--organization``, if you want to
import data to a specific organization, you can give its UUID for the same,
by default the data is added to the first found organization, eg::

    ./manage.py upgrade_from_django_freeradius --organization 900856da-c89a-412d-8fee-45a9c763ca0b

.. note::
    You can follow the `tutorial to migrate database from django-freeradius <https://github.com/openwisp/django-freeradius/blob/master/README.rst>`_.

.. warning::
    It is not possible to export user credential data for radiusbatch created using prefix, please manually preserve the PDF files if you want to access the data in the future.

``convert_called_station_id``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If an installation uses a centralized captive portal, the value of "Called Station ID" of
RADIUS Session will show the MAC address of the captive portal instead of access points.
This command will update the "Called Station ID" to reflect the MAC address of the access points
using information from OpenVPN. It requires installing ``openvpn_status``,
which can be installed using the following command

.. code-block:: shell

    pip install openwisp-radius[openvpn_status]

In order to work, this command requires to be configured via the
`OPENWISP_RADIUS_CALLED_STATION_IDS <./settings.html#openwisp-radius-called-station-ids>`_ setting.

Use the following command if you want to perform this operation for all
RADIUS sessions that meet criteria of ``OPENWISP_RADIUS_CALLED_STATION_IDS``
setting.

.. code-block:: shell

    ./manage.py convert_called_station_id

You can also convert the "Called Station ID" of a particular RADIUS session by
replacing session's ``unique_id`` in the following command:

.. code-block:: shell

    ./manage.py convert_called_station_id --unique_id=<session_unique_id>

.. note::

    If you encounter ``ParseError`` for datetime data, you can set the datetime format
    of the parser using `OPENWISP_RADIUS_OPENVPN_DATETIME_FORMAT <./settings.html#openwisp-radius-openvpn-datetime-format>`_
    setting.

.. note::

    ``convert_called_station_id`` command will only operate on open RADIUS sessions,
    i.e. the "stop_time" field is None.

    But if you are converting a single RADIUS session, it will operate on
    it even if the session is closed.
