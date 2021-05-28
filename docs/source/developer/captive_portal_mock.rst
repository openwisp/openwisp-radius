=========================
Captive portal mock views
=========================

The development environment of openwisp-radius provides two URLs that mock
the behavior of a captive portal, these URLs can be used when testing
frontend applications like
`openwisp-wifi-login-pages <https://github.com/openwisp/openwisp-wifi-login-pages>`_
during development.

.. note::
   These views are meant to be used just for development and testing.

Captive Portal Login Mock View
------------------------------

- **URL**: ``http://localhost:8000/captive-portal-mock/login/``.
- **POST fields**: ``auth_pass`` or ``password``.

This view looks for ``auth_pass`` or ``password`` in the POST request data,
and if it finds anything will try to look for any ``RadiusToken`` instance
having its key equal to this value, and if it does find one, it will create a
radius session (an entry in the ``radacct`` table) related to the user
to which the radius token belongs, provided there's no other open session
for the same user.

Captive Portal Logout Mock View
-------------------------------

- **URL**: ``http://localhost:8000/captive-portal-mock/logout/``.
- **POST fields**: ``logout_id``.

This view looks for an entry in the ``radacct`` table with ``session_id``
equals to what is passed in the ``logout_id`` POST field and if it finds
one, it flags the session as terminated with ``User-Request``
termination cause and populates the ``stop_time`` column with the current
UTC time.
