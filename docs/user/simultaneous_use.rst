Limiting concurrent sessions (``Simultaneous-Use``)
===================================================

``Simultaneous-Use`` is a FreeRADIUS feature that restricts how many
sessions a user can keep active at the same time. When the maximum limit
is reached and the user attempts to start another session from a different
client device, the authorization is rejected with the following RADIUS
reply message:

.. code-block:: text

    You are already logged in - access denied

FreeRADIUS can enforce this check through its ``sql`` module, but that's
not multi-tenant aware: this can cause issues when a user belongs to
multiple organizations with different session limits, potentially
resulting in wrong limits being applied.

To address this, OpenWISP RADIUS provides a multi-tenant aware
``Simultaneous-Use`` check in its authorization REST API endpoint.

Configuring Simultaneous-Use Check
----------------------------------

Add the ``Simultaneous-Use`` RADIUS check to the desired RADIUS group by
following these steps:

1. In the admin interface, navigate to **RADIUS** in the left-hand menu.
2. Go to **Groups**.
3. Select the group you want to configure.
4. In the **GROUP CHECKS** section, click on **Add another Group check**.
5. Fill in the fields as follows:

   - **Attribute**: ``Simultaneous-Use``
   - **Operator**: ``:=``
   - **Value**: ``1`` (or any number greater than 0; `1` limits users to
     one concurrent session)

   .. image:: ../images/simultaneous-use-radius-check.png
       :alt: Example of setting Idle-Timeout to 240

.. important::

    When using Simultaneous-Use, it is recommended to add an
    ``Idle-Timeout`` RADIUS reply to the same RADIUS group, with a low
    value (below 300 seconds). This ensures inactive sessions are cleared
    quickly, preventing users from being blocked due to stale sessions.

6. For the same radius group, in the **GROUP REPLIES** section, click on
   **Add another Group reply**.
7. Fill in the fields as follows:

   - **Attribute**: ``Idle-Timeout``
   - **Operator**: ``=``
   - **Value**: ``240``

   .. image:: ../images/idle-timeout-radius-reply.png
       :alt: Example of setting Idle-Timeout to 240

8. Click on **Save and continue editing** at the bottom of the page.

Disabling the ``Simultaneous-Use`` check
----------------------------------------

The ``Simultaneous-Use`` feature is **enabled by default**.

It can be disabled with the :ref:`OPENWISP_RADIUS_SIMULTANEOUS_USE_ENABLED
<openwisp_radius_simultaneous_use_enabled>` setting.

This is useful if you already rely on another FreeRADIUS module to enforce
``Simultaneous-Use`` and do not need the OpenWISP implementation.
