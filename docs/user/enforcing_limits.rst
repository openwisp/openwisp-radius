Enforcing Session Limits
========================

The default freeradius schema does not include a table where groups are
stored, but openwisp-radius adds a model called ``RadiusGroup`` and alters
the default freeradius schema to add some optional foreign-keys from other
tables like:

- ``radgroupcheck``
- ``radgroupreply``
- ``radusergroup``

These foreign keys make it easier to automate many synchronization and
integrity checks between the ``RadiusGroup`` table and its related tables
but they are not strictly mandatory from the database point of view: their
value can be ``NULL`` and their presence and validation is handled at
application level, this makes it easy to use existing freeradius
databases.

For each group, checks and replies can be specified directly in the edit
page of a Radius Group (``admin`` > ``groups`` > ``add group`` or ``change
group``).

Default Groups
--------------

Some groups are created automatically by **openwisp-radius** during the
initial migrations:

- ``users``: this is the default group which limits users sessions to 3
  hours and 300 MB (daily)
- ``power-users``: this group does not have any check, therefore users who
  are members of this group won't be limited in any way

You can customize the checks and the replies of these groups, as well as
create new groups according to your needs and preferences.

**Note on the default group**: keep in mind that the group flagged as
default will by automatically assigned to new users, it cannot be deleted
nor it can be flagged as non-default: to set another group as default
simply check that group as the default one, save and **openwisp-radius**
will remove the default flag from the old default group.

.. _radius_counters:

How Limits are Enforced: Counters
---------------------------------

In Freeradius, this kind of feature is implemented with the
`rlm_sqlcounter <https://wiki.freeradius.org/modules/Rlm_sqlcounter>`_.

The problem with this FreeRADIUS module is that it doesn't know about
OpenWISP, so it does not support multi-tenancy. This means that if
multiple organizations are using the OpenWISP instance, it's possible that
a user may be an end user of multiple organizations and hence have one
radius group assigned for each, but the *sqlcounter* module will not
understand the right group to choose when enforcing limits, with the
result that the enforcing of limits will not work as expected, unless one
FreeRADIUS site with different *sqlcounter* configurations is created for
each organization using the system, which is doable but cumbersome to
maintain.

For the reasons explained above, an alternative counter feature has been
implemented in the authorize API endpoint of OpenWISP RADIUS.

The default counters available are described below.

``DailyCounter``
~~~~~~~~~~~~~~~~

This counter is used to limit the amount of time users can use the network
every day. It works by checking whether the total session time of a user
during a specific day is below the value indicated in the
``Max-Daily-Session`` group check attribute, sending the remaining session
time with a ``Session-Timeout`` reply message or rejecting the
authorization if the limit has been passed.

.. _radius_daily_traffic_counter:

``DailyTrafficCounter``
~~~~~~~~~~~~~~~~~~~~~~~

This counter is used to limit the amount of traffic users can consume
every day. It works by checking whether the total amount of download plus
upload octets (bytes consumed) is below the value indicated in the
``Max-Daily-Session-Traffic`` group check attribute, sending the remaining
octets with a reply message or rejecting the authorization if the limit
has been passed.

The attributes used for the check and or the reply message are
configurable because it can differ from NAS to NAS, see
:ref:`radius_traffic_counter_check_name`
:ref:`radius_traffic_counter_reply_name` for more information.

``MonthlyTrafficCounter``
~~~~~~~~~~~~~~~~~~~~~~~~~

This counter is used to limit the amount of traffic users can consume
every solar month. It works by checking whether the total amount of
download plus upload octets (bytes consumed) is below the value indicated
in the ``Max-Monthly-Session-Traffic`` group check attribute, sending the
remaining octets with a reply message or rejecting the authorization if
the limit has been passed.

The reply message is configurable because it can differ from NAS to NAS,
:ref:`radius_traffic_counter_reply_name` for more information.

``MonthlySubscriptionTrafficCounter``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. important::

    This counter is not enabled by default. It can be enabled via the
    :ref:`radius_counter_related_settings`.

Same as ``MonthlyTrafficCounter``, but with the difference that the reset
period depends on the day in which the user subscribed to the service: if
the user signed up (or their account was created by an admin) on a date
like November 15 2022, the reset period will start on the *15th day* of
every month.

Database Support
~~~~~~~~~~~~~~~~

The counters described above are available for PostgreSQL, MySQL, SQLite
and are enabled by default.

There's a different class of each counter for each database, because the
query is executed with raw SQL defined on each class, instead of the
classic django-ORM approach which is database agnostic.

It was implemented this way to ensure maximum flexibility and adherence to
the FreeRADIUS *sqlcounter* implementation.

Django Settings
~~~~~~~~~~~~~~~

The settings available to control the behavior of counters are described
in :ref:`radius_counter_related_settings`.

Writing Custom Counter Classes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to write custom counter classes to satisfy any need.

The easiest way is to subclass
``openwisp_radius.counters.base.BaseCounter``, then implement at least the
following attributes:

- ``counter_name``: name of the counter, used internally for debugging;
- ``check_name``: attribute name used in the database lookup to the group
  check table;
- ``reply_name``: attribute name sent in the reply message;
- ``reset``: reset period, either ``daily``, ``weekly``, ``monthly``,
  ``monthly_subscription`` or ``never``;
- ``sql``: the raw SQL query to execute;
- ``get_sql_params``: a method which returns a list of the arguments
  passed to the interpolation of the raw SQL query.

Please look at the source code of OpenWISP RADIUS to find out more.

- `openwisp_radius.counters.base
  <https://github.com/openwisp/openwisp-radius/blob/master/openwisp_radius/counters/base.py>`_
- `openwisp_radius.counters.postgresql
  <https://github.com/openwisp/openwisp-radius/tree/master/openwisp_radius/counters/postgresql>`_

Once the new class is ready, you will need to add it to
:ref:`radius_counters_setting`.

It is also possible to implement a check class in a completely custom
fashion (that is, not inheriting from ``BaseCounter``), the only
requirements are:

- the class must have a constructor (``__init__`` method) identical to the
  one used in the ``BaseCounter`` class;
- the class must have a ``check`` method which doesn't need any required
  argument and returns the remaining counter value or raises
  ``MaxQuotaReached`` if the limit has been reached and the authorization
  should be rejected; This method may return ``None`` if no additional
  RADIUS attribute needs to be added to the response.
