Available settings
------------------

Admin related settings
======================

These settings control details of the administration interface of openwisp-radius.

``OPENWISP_RADIUS_EDITABLE_ACCOUNTING``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Whether ``radacct`` entries are editable from the django admin or not.

``OPENWISP_RADIUS_EDITABLE_POSTAUTH``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Whether ``postauth`` logs are editable from the django admin or not.

``OPENWISP_RADIUS_GROUPCHECK_ADMIN``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Direct editing of group checks items is disabled by default because
these can be edited through inline items in the Radius Group
admin (Freeradius > Groups).

*This is done with the aim of simplifying the admin interface and avoid
overwhelming users with too many options*.

If for some reason you need to enable direct editing of group checks
you can do so by setting this to ``True``.

``OPENWISP_RADIUS_GROUPREPLY_ADMIN``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Direct editing of group reply items is disabled by default because
these can be edited through inline items in the Radius Group
admin (Freeradius > Groups).

*This is done with the aim of simplifying the admin interface and avoid
overwhelming users with too many options*.

If for some reason you need to enable direct editing of group replies
you can do so by setting this to ``True``.

``OPENWISP_RADIUS_USERGROUP_ADMIN``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Direct editing of user group items (``radusergroup``) is disabled by default
because these can be edited through inline items in the User
admin (Users and Organizations > Users).

*This is done with the aim of simplifying the admin interface and avoid
overwhelming users with too many options*.

If for some reason you need to enable direct editing of user group items
you can do so by setting this to ``True``.

Model related settings
======================

These settings control details of the openwisp-radius model classes.

``OPENWISP_RADIUS_DEFAULT_SECRET_FORMAT``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``NT-Password``

The default encryption format for storing radius check values.

``OPENWISP_RADIUS_DISABLED_SECRET_FORMATS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``[]``

A list of disabled encryption formats, by default all formats are
enabled in order to keep backward compatibility with legacy systems.

``OPENWISP_RADIUS_RADCHECK_SECRET_VALIDATORS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**:

.. code-block:: python

    {'regexp_lowercase': '[a-z]+',
     'regexp_uppercase': '[A-Z]+',
     'regexp_number': '[0-9]+',
     'regexp_special': '[\!\%\-_+=\[\]\
                       {\}\:\,\.\?\<\>\(\)\;]+'}

Regular expressions regulating the password validation;
by default the following character families are required:

- a lowercase character
- an uppercase character
- a number
- a special character

``OPENWISP_RADIUS_BATCH_DEFAULT_PASSWORD_LENGTH``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``8``

The default password length of the auto generated passwords while
batch addition of users from the csv.

``OPENWISP_RADIUS_BATCH_DELETE_EXPIRED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``18``

It is the number of months after which the expired users are deleted.

``OPENWISP_RADIUS_BATCH_PDF_TEMPLATE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is the template used to generate the pdf when users are being generated using the batch add users feature using the prefix.

The value should be the absolute path to the template of the pdf.

``OPENWISP_RADIUS_EXTRA_NAS_TYPES``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``tuple()``

This setting can be used to add custom NAS types that can be used from the
admin interface when managing NAS instances.

For example, you want a custom NAS type called ``cisco``, you would add
the following to your project ``settings.py``:

.. code-block:: python

    OPENWISP_RADIUS_EXTRA_NAS_TYPES = (
        ('cisco', 'Cisco Router'),
    )

``OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``[]``

List of host IP addresses allowed to consume the freeradius
API endpoints (Authorize, Accounting and Postauth), i.e the value
of this option should be the IP address of your freeradius
instance. Example: If your freeradius instance is running on
the same host machine as OpenWISP, the value should be ``127.0.0.1``.
Similarly, if your freeradius instance is on a different host in
the private network, the value should be the private IP of freeradius
host like ``192.0.2.50``. If your freeradius is on a public network,
please use the public IP of your freeradius instance.

This value can be overridden per organization in the organization
change page. You can skip setting this option if you intend to set
it from organization change page for each organization.

.. image:: /images/freeradius_allowed_hosts.png
   :alt: Organization change page freeradius settings

.. code-block:: python

    OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS = ['127.0.0.1', '192.0.2.10']

If this option and organization change page option are both
empty, then all freeradius API requests for the organization
will return ``403``.

``OPENWISP_RADIUS_MAX_CSV_FILE_SIZE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+----------------------------+
| **type**:    | ``int``                    |
+--------------+----------------------------+
| **default**: |  `5 * 1024 * 1024` (5 MB)  |
+--------------+----------------------------+

This setting can be used to set the maximum size limit for firmware images, eg:

.. code-block:: python

    OPENWISP_RADIUS_MAX_CSV_FILE_SIZE = 10 * 1024 * 1024  # 10MB

**Notes**:

- Value must be specified in bytes. ``None`` means unlimited.

API and user token related settings
===================================

These settings control details related to the API and the radius user token.

``OPENWISP_RADIUS_API``
~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``True``

Indicates whether the REST API of openwisp-radius is enabled or not.

``OPENWISP_RADIUS_DISPOSABLE_RADIUS_USER_TOKEN``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``True``

Radius user tokens are used for authorizing users.

When this setting is ``True`` radius user tokens are deleted right after a successful
authorization is performed. This reduces the possibility of attackers reusing
the access tokens and posing as other users if they manage to intercept it somehow.

``OPENWISP_RADIUS_API_AUTHORIZE_REJECT``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Indicates wether the `Authorize API view <api.html#Authorize>`_ will return
``{"control:Auth-Type": "Reject"}`` or not.

Rejecting an authorization request explicitly will prevent freeradius from
attempting to perform authorization with other mechanisms (eg: radius checks, LDAP, etc.).

When set to ``False``, if an authorization request fails, the API will respond with
``None``, which will allow freeradius to keep attempting to authorize the request
with other freeradius modules.

Set this to ``True`` if you are performing authorization exclusively through the REST API.

``OPENWISP_RADIUS_API_ACCOUNTING_AUTO_GROUP``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``True``

When this setting is enabled, every accounting instance saved from the API will have
its ``groupname`` attribute automatically filled in.
The value filled in will be the ``groupname`` of the ``RadiusUserGroup`` of the highest
priority among the RadiusUserGroups related to the user with the ``username`` as in the
accounting instance.
In the event there is no user in the database corresponding to the ``username`` in the
accounting instance, the failure will be logged with ``warning`` level but the accounting
will be saved as usual.

``OPENWISP_RADIUS_ALLOWED_MOBILE_PREFIXES``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``[]``

This setting is used to specify a list of international mobile prefixes which should
be allowed to register into the system via the `user registration API <api.html#user-registration>`_.

That is, only users with phone numbers using the specified international prefixes will
be allowed to register.

Leaving this unset or setting it to an empty list (``[]``) will effectively allow
any international mobile prefix to register (which is the default setting).

For example:

.. code-block:: python

    OPENWISP_RADIUS_ALLOWED_MOBILE_PREFIXES = ['+44', '+237']

Using the setting above will only allow phone numbers from the UK (``+44``)
or Cameroon (``+237``).

**Note:** this setting is applicable only for organizations which have enabled SMS verification.

``OPENWISP_RADIUS_OPTIONAL_REGISTRATION_FIELDS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**:

.. code-block:: python

    {
        'first_name': 'disabled',
        'last_name': 'disabled',
        'birth_date': 'disabled',
        'location': 'disabled',
    }

This global setting is used to specify if the optional user fields
(``first_name``, ``last_name``, ``location`` and ``birth_date``)
shall be disabled (hence ignored), allowed or required in the
`User Registration API <api.html#user-registration>`_.

The allowed values are:

- ``disabled``: (**default**) the field is disabled.
- ``allowed``: the field is allowed but not mandatory.
- ``mandatory``: the field is mandatory.

For example:

.. code-block:: python

    OPENWISP_RADIUS_OPTIONAL_REGISTRATION_FIELDS = {
        'first_name': 'disabled',
        'last_name': 'disabled',
        'birth_date': 'mandatory',
        'location': 'allowed',
    }

Means:

- ``first_name`` and ``last_name`` fields are not required and their values
  if provided are ignored.
- ``location`` field is not required but its value will
  be saved to the database if provided.
- ``birth_date`` field is required and a ``ValidationError``
  exception is raised if its value is not provided.

The setting for each field can also be overridden at organization level
if needed, by going to
``Home › Users and Organizations › Organizations > Edit organization`` and
then scrolling down to ``ORGANIZATION RADIUS SETTINGS``.

.. image:: /images/optional_fields.png
    :alt: optional field setting

By default the fields at organization level hold a ``NULL`` value,
which means that the global setting specified in ``settings.py`` will
be used.

``OPENWISP_RADIUS_PASSWORD_RESET_URLS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**:

.. code-block:: python

    {
        'default': 'https://{site}/{organization}/password/reset/confirm/{uid}/{token}'
    }

A dictionary representing the frontend URLs through which end users can complete
the password reset operation.

The frontend could be `openwisp-wifi-login-pages <https://github.com/openwisp/openwisp-wifi-login-pages>`_
or another in-house captive page solution.

Keys of the dictionary must be either UUID of organizations or ``default``, which is the fallback URL
that will be used in case there's no customized URL for a specific organization.

The meaning of the variables in the string is the following:

- ``{site}``: site domain as defined in the
  `django site framework <https://docs.djangoproject.com/en/dev/ref/contrib/sites/>`_
  (defaults to example.com and an be changed through the django admin)
- ``{organization}``: organization slug
- ``{uid}``: uid of the password reset request
- ``{token}``: token of the password reset request

If you're using `openwisp-wifi-login-pages <https://github.com/openwisp/openwisp-wifi-login-pages>`_,
the configuration is fairly simple, in case the nodejs app is installed in the same domain
of openwisp-radius, you only have to ensure the domain field in the main Site object is correct,
if instead the nodejs app is deployed on a different domain, say ``login.wifiservice.com``,
the configuration should be simply changed to:

.. code-block:: python

    {
        'default': 'https://login.wifiservice.com/{organization}/password/reset/confirm/{uid}/{token}'
    }

Email related settings
======================

Emails can be sent to users whose usernames or passwords have been auto-generated.
The content of these emails can be customized with the settings explained below.

``OPENWISP_RADIUS_BATCH_MAIL_SUBJECT``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``Credentials``

It is the subject of the mail to be sent to the users. Eg: ``Login Credentials``.

``OPENWISP_RADIUS_BATCH_MAIL_MESSAGE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``username: {}, password: {}``

The message should be a string in the format ``Your username is {} and password is {}``.

The text could be anything but should have the format string operator ``{}`` for
``.format`` operations to work.

``OPENWISP_RADIUS_BATCH_MAIL_SENDER``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``settings.DEFAULT_FROM_EMAIL``

It is the sender email which is also to be configured in the SMTP settings.
The default sender email is a common setting from the
`Django core settings  <https://docs.djangoproject.com/en/dev/ref/settings/#default-from-email>`_
under ``DEFAULT_FROM_EMAIL``.
Currently, ``DEFAULT_FROM_EMAIL`` is set to to ``webmaster@localhost``.
