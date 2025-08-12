Simultaneous session limits (Simultaneous-Use)
==============================================

``Simultaneous-Use`` limits how many sessions a user can have active at
the same time.

During authorization, OpenWISP RADIUS counts the user's active sessions
and compares them with the limit set in their RADIUS group. If the number
of active sessions is **equal to or greater than** the limit, access is
denied with:

.. code-block:: text

    You are already logged in - access denied

.. note::

    A value of ``0`` or negative means **no limit**.

You can enable this feature by setting
:ref:`OPENWISP_RADIUS_SIMULTANEOUS_USE_ENABLED
<openwisp_radius_simultaneous_use_enabled>` to ``True`` in your Django's
project settings.

.. code-block:: python

    # In your_project/settings.py
    OPENWISP_RADIUS_SIMULTANEOUS_USE_ENABLED = True

.. important::

    When using ``Simultaneous-Use``, it is recommended to set the
    ``Idle-Timeout`` attribute to a low value (below ``300`` seconds).
