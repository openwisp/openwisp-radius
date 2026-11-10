Registration of new users
=========================

openwisp-radius uses `django-rest-auth
<https://github.com/jazzband/dj-rest-auth/>`_ which provides registration
of new users via REST API so you can implement registration and password
reset directly from your captive page.

.. important::

    Registration, social login, and SAML login are unavailable for
    disabled organizations. Such requests are rejected with ``403
    Forbidden``.

The registration API endpoint is described in :ref:`API: User Registration
<radius_user_registration>`.

If you need users to self-register to a public wifi service, we suggest to
take a look at :doc:`OpenWISP WiFi Login Pages </wifi-login-pages/index>`,
which is built to work with openwisp-radius.
