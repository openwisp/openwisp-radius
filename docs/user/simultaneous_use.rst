Limiting concurrent sessions (Simultaneous-Use)
===============================================

``Simultaneous-Use`` is a RADIUS feature that limits how many sessions a
user can have active at the same time. If the user reaches the configured
limit and tries to start another session, the new session is rejected with
the following message

.. code-block:: text

    You are already logged in - access denied

While FreeRADIUS can enforce this check via its ``sql`` module, it does
not handle multi-tenancy. As a result, if a user belongs to multiple
organizations with different session limits, it may apply an incorrect
limit. To avoid this, OpenWISP RADIUS enforces ``Simultaneous-Use`` in its
authorization API, ensuring the correct limit is applied according to the
user's organization.

Enabling and Configuring Simultaneous-Use
-----------------------------------------

Enable this feature by setting
:ref:`OPENWISP_RADIUS_SIMULTANEOUS_USE_ENABLED
<openwisp_radius_simultaneous_use_enabled>` to ``True`` in your Django
project settings:

.. code-block:: python

    OPENWISP_RADIUS_SIMULTANEOUS_USE_ENABLED = True

.. include:: /partials/settings-note.rst

Then, add the ``Simultaneous-Use`` RADIUS check to the desired RADIUS
group:

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
