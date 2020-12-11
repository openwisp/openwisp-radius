=========================
Registration of new users
=========================

openwisp-radius uses `django-rest-auth <https://github.com/jazzband/dj-rest-auth/>`_
which provides registration of new users via REST API so you can implement
registration and password reset directly from your captive page.

The registration API endpoint is described in `API: User Registration <api.html#user-registration>`_.

If you need users to self-register to a public wifi service, we suggest
to take a look at `openwisp-wifi-login-pages <https://github.com/openwisp/openwisp-wifi-login-pages>`_,
which is built to work with openwisp-radius.
