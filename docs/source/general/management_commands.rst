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
