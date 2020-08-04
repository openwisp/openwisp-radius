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
