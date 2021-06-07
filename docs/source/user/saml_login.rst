=====================
Single Sign-On (SAML)
=====================

SAML login is supported by generating an additional temporary token right
after users authenticates via SSO, the user is then redirected to the
captive page with two querystring parameters: ``username`` and ``token``.

The captive page must recognize these two parameters and automatically perform
the submit action of the login form: ``username`` should obviously used for the
username field, while ``token`` should be used for the password field.

The internal REST API of openwisp-radius will recognize the token and authorize
the user.

This kind of implementation allows to implement the SAML login with any captive
portal which already supports the RADIUS protocol because it's totally transparent
for it, that is, the captive portal doesn't even know the user is signing-in with
a SSO.

.. note::
   If you're building a public wifi service, we suggest
   to take a look at `openwisp-wifi-login-pages <https://github.com/openwisp/openwisp-wifi-login-pages>`_,
   which is built to work with openwisp-radius.

Setup
-----

Install required system dependencies:

    sudo apt install xmlsec1

Install Python dependencies::

    pip install openwisp-radius[saml]

Ensure your ``settings.py`` looks like the following:

.. code-block:: python

    INSTALLED_APPS = [
        # ... other apps ..
        # apps needed for SAML login
        'rest_framework.authtoken',
        'django.contrib.sites',
        'allauth',
        'allauth.account',
        'djangosaml2'
    ]

    SITE_ID = 1

    # Update AUTHENTICATION_BACKENDS
    AUTHENTICATION_BACKENDS = (
        'openwisp_users.backends.UsersAuthenticationBackend',
        'djangosaml2.backends.Saml2Backend', # <- add for SAML login
    )

    # Update MIDDLEWARE
    MIDDLEWARE = [
        # ... other middlewares ...
        'djangosaml2.middleware.SamlSessionMiddleware',
    ]

Ensure your main ``urls.py`` contains the ``allauth.urls``:

.. code-block:: python

    urlpatterns = [
        # .. other urls ...
        path('accounts/', include('openwisp_users.accounts.urls')),
    ]

Configure the SAML Settings
---------------------------

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

    <a href="https://openwisp2.mywifiproject.com/radius/saml2/login/?RelayState=https://captivepage.mywifiproject.com%3Forg%3Ddefault
       class="button">
       Log in with SSO
    </a>

Substitute ``openwisp2.mywifiproject.com``, ``https://captivepage.mywifiproject.com``
and ``default`` with the hostname of your openwisp-radius instance, your captive
page and the organization slug respectively.

Alternatively, you can take a look at
`openwisp-wifi-login-pages <https://github.com/openwisp/openwisp-wifi-login-pages>`_,
which provides buttons for Single Sign-On (SAML) by default.
