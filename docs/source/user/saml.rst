.. _saml_:

Single Sign-On (SAML)
=====================

.. important::

    The SAML registration method is disabled by default.

    In order to enable this feature you have to follow the :ref:`SAML
    setup instructions <setup_saml>` below and then activate it via
    :ref:`global setting or from the admin interface
    <openwisp_radius_saml_registration_enabled>`.

`SAML <http://saml.xml.org/about-saml>`_ is supported by generating an
additional temporary token right after users authenticates via SSO, the
user is then redirected to the captive page with 3 querystring parameters:

- ``username``
- ``token`` (REST auth token)
- ``login_method=saml``

The captive page must recognize these two parameters, validate the token
and automatically perform the submit action of the captive portal login
form: ``username`` should obviously used for the username field, while
``token`` should be used for the password field.

The third parameter, ``login_method=saml``, is needed because it allows
the captive page to remember that the user logged in via SAML, because it
will need to perform the :ref:`SAML logout <logout>` later on.

The internal REST API of openwisp-radius will recognize the token and
authorize the user.

This kind of implementation allows to support SAML with any captive portal
which already supports the RADIUS protocol because it's totally
transparent for it, that is, the captive portal doesn't even know the user
is signing-in with a SSO.

.. note::

    If you're building a public wifi service, we suggest to take a look at
    `openwisp-wifi-login-pages
    <https://github.com/openwisp/openwisp-wifi-login-pages>`_, which is
    built to work with openwisp-radius.

.. _setup_saml:

Setup
-----

Install required system dependencies:

::

    sudo apt install xmlsec1

Install Python dependencies:

::

    pip install openwisp-radius[saml]

Ensure your ``settings.py`` looks like the following:

.. code-block:: python

    INSTALLED_APPS = [
        # ... other apps ..
        # apps needed for SAML login
        "rest_framework.authtoken",
        "django.contrib.sites",
        "allauth",
        "allauth.account",
        "djangosaml2",
    ]

    SITE_ID = 1

    # Update AUTHENTICATION_BACKENDS
    AUTHENTICATION_BACKENDS = (
        "openwisp_users.backends.UsersAuthenticationBackend",
        "openwisp_radius.saml.backends.OpenwispRadiusSaml2Backend",  # <- add for SAML login
    )

    # Update MIDDLEWARE
    MIDDLEWARE = [
        # ... other middlewares ...
        "djangosaml2.middleware.SamlSessionMiddleware",
    ]

Ensure your main ``urls.py`` contains the
``openwisp_users.accounts.urls``:

.. code-block:: python

    urlpatterns = [
        # .. other urls ...
        path("accounts/", include("openwisp_users.accounts.urls")),
    ]

Configure the djangosaml2 settings
----------------------------------

Refer to the djangosaml2 documentation to find out `how to configure
required settings for SAML
<https://djangosaml2.readthedocs.io/contents/setup.html#configuration>`_.

Captive page button example
---------------------------

After successfully configuring SAML settings for your Identity Provider,
you will need an HTML button similar to the one in the following example.

This example needs the slug of the organization to assign the new user to
the right organization:

.. code-block:: html

    <a href="https://openwisp2.mywifiproject.com/radius/saml2/login/?RelayState=https://captivepage.mywifiproject.com%3Forg%3Ddefault"
       class="button">
       Log in with SSO
    </a>

Substitute ``openwisp2.mywifiproject.com``,
``https://captivepage.mywifiproject.com`` and ``default`` with the
hostname of your openwisp-radius instance, your captive page and the
organization slug respectively.

Alternatively, you can take a look at `openwisp-wifi-login-pages
<https://github.com/openwisp/openwisp-wifi-login-pages>`_, which provides
buttons for Single Sign-On (SAML) by default.

.. _logout:

Logout
------

When logging out a user which logged in via SAML, the captive page should
also call the SAML logout URL: ``/radius/saml2/logout/``.

The `openwisp-wifi-login-pages
<https://github.com/openwisp/openwisp-wifi-login-pages>`_ app supports
this with minimal configuration, refer to the `"Configuring SAML Login &
Logout"
<https://github.com/openwisp/openwisp-wifi-login-pages#configuring-saml-login--logout>`_
section.

Settings
--------

See :ref:`SAML related settings <saml_settings>`.

FAQs
----

.. _preventing_change_in_username_of_registered_user:

Preventing change in username of a registered user
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``djangosaml2`` library requires configuring
``SAML_DJANGO_USER_MAIN_ATTRIBUTE`` setting which serves as the primary
lookup value for User objects. Whenever a user logs in or registers
through the SAML method, a database query is made to check whether such a
user already exists. This lookup is done using the value of
``SAML_DJANGO_USER_MAIN_ATTRIBUTE`` setting. If a match is found, the
details of the user are updated with the information received from SAML
Identity Provider.

If a user (who has registered on OpenWISP with a different method from
SAML) logs into OpenWISP with SAML, then the default behaviour of OpenWISP
RADIUS prevents updating username of this user. Because, this operation
could render the user's old credentials useless. If you want to update the
username in such scenarios with details received from Identity Provider,
set :ref:`OPENWISP_RADIUS_SAML_UPDATES_PRE_EXISTING_USERNAME
<openwisp_radius_saml_updates_pre_existing_username>` to ``True``.
