========================
Enforcing session limits
========================

The default freeradius schema does not include a table where groups are stored,
but openwisp-radius adds a model called ``RadiusGroup`` and alters the default
freeradius schema to add some optional foreign-keys from other tables like:

- ``radgroupcheck``
- ``radgroupreply``
- ``radusergroup``

These foreign keys make it easier to automate many synchronization and integrity
checks between the ``RadiusGroup`` table and its related tables but they are
not strictly mandatory from the database point of view:
their value can be ``NULL`` and their presence and validation is handled at
application level, this makes it easy to use existing freeradius databases.

For each group, checks and replies can be specified directly in the edit page
of a Radius Group (``admin`` > ``groups`` > ``add group`` or ``change group``).

Default groups
--------------

Some groups are created automatically by **openwisp-radius** during the initial
migrations:

- ``users``: this is the default group which limits users sessions
  to 3 hours and 300 MB (daily)
- ``power-users``: this group does not have any check, therefore users who
  are members of this group won't be limited in any way

You can customize the checks and the replies of these groups, as well as create
new groups according to your needs and preferences.

**Note on the default group**: keep in mind that the group flagged as
default will by automatically assigned to new users, it cannot be deleted nor
it can be flagged as non-default: to set another group as default simply check
that group as the default one, save and **openwisp-radius** will remove the
default flag from the old default group.

Freeradius configuration
------------------------

Ensure the ``sqlcounter`` module is enabled and configured as described in
:ref:`configure-sqlcounters`.
