============
Social Login
============

Social login is supported by generating an additional temporary token right
after users perform the social sign-in, the user is then redirected to the
captive page with two querystring parameters: ``username`` and ``token``.

The captive page must recognize these two parameters and automatically perform
the submit action of the login form: ``username`` should obviously used for the
username field, while ``token`` should be used for the password field.

The internal REST API of openwisp-radius will recognize the token and authorize
the user.

This kind of implementation allows to implement the social login with any captive
portal which already supports the RADIUS protocol because it's totally transparent
for it, that is, the captive portal doesn't even know the user is signing-in with
a social network.

.. note::
   If you're building a public wifi service, we suggest
   to take a look at `openwisp-wifi-login-pages <https://github.com/openwisp/openwisp-wifi-login-pages>`_,
   which is built to work with openwisp-radius.

Setup
-----

Install ``django-allauth``::

    pip install django-allauth

Ensure your ``settings.py`` looks like the following (we will show how to
configure of the facebook social provider):

.. code-block:: python

    INSTALLED_APPS = [
        # ... other apps ..
        # apps needed for social login
        'rest_framework.authtoken',
        'django.contrib.sites',
        'allauth',
        'allauth.account',
        'allauth.socialaccount',
        # showing facebook as an example
        # to configure social login with other social networks
        # refer to the django-allauth documentation
        'allauth.socialaccount.providers.facebook',
    ]

    SITE_ID = 1

    # showing facebook as an example
    # to configure social login with other social networks
    # refer to the django-allauth documentation
    SOCIALACCOUNT_PROVIDERS = {
        'facebook': {
            'METHOD': 'oauth2',
            'SCOPE': ['email', 'public_profile'],
            'AUTH_PARAMS': {'auth_type': 'reauthenticate'},
            'INIT_PARAMS': {'cookie': True},
            'FIELDS': [
                'id',
                'email',
                'name',
                'first_name',
                'last_name',
                'verified',
            ],
            'VERIFIED_EMAIL': True,
        }
    }

Ensure your main ``urls.py`` contains the ``allauth.urls``:

.. code-block:: python

    urlpatterns = [
        # .. other urls ...
        path('accounts/', include('allauth.urls')),
    ]

Configure the social account application
----------------------------------------

Refer to the django-allauth documentation to find out `how to complete the
configuration of a sample facebook login app
<https://django-allauth.readthedocs.io/en/latest/providers.html#facebook>`_.

Captive page button example
---------------------------

Following the previous example configuration with facebook, in your captive page
you will need an HTML button similar to the ones in the following examples.

This example needs the slug of the organization to assign the new user to
the right organization:

.. code-block:: html

    <a href="https://openwisp2.mywifiproject.com/accounts/facebook/login/?next=%2Fradius%2Fsocial-login%2Fdefault%2F%3Fcp%3Dhttps%3A%2F%2Fcaptivepage.mywifiproject.com%2F%26last%3D"
       class="button">Log in with Facebook
    </a>

Substitute ``openwisp2.mywifiproject.com``, ``captivepage.mywifiproject.com``
and ``default`` with the hostname of your openwisp-radius instance, your captive
page and the organization slug respectively.

Alternatively, you can take a look at
`openwisp-wifi-login-pages <https://github.com/openwisp/openwisp-wifi-login-pages>`_,
which provides buttons for Facebook, Google and Twitter by default.
