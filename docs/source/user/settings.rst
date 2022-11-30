Available settings
------------------

Admin related settings
======================

These settings control details of the administration interface of openwisp-radius.

.. note::

    The values of overridden settings fields do not change even when
    the global defaults are changed.

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

``OPENWISP_RADIUS_USER_ADMIN_RADIUSTOKEN_INLINE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

The functionality of editing a user's ``RadiusToken`` directly
through an inline from the user admin page is disabled by default.

*This is done with the aim of simplifying the admin interface and avoid
overwhelming users with too many options*.

If for some reason you need to enable editing user's ``RadiusToken``
from the user admin page, you can do so by setting this to ``True``.

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

.. _openwisp_radius_freeradius_allowed_hosts:

``OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``[]``

List of host IP addresses or subnets allowed to consume the freeradius
API endpoints (Authorize, Accounting and Postauth), i.e the value
of this option should be the IP address of your freeradius
instance. Example: If your freeradius instance is running on
the same host machine as OpenWISP, the value should be ``127.0.0.1``.
Similarly, if your freeradius instance is on a different host in
the private network, the value should be the private IP of freeradius
host like ``192.0.2.50``. If your freeradius is on a public network,
please use the public IP of your freeradius instance.

You can use subnets when freeradius is hosted on a variable IP, eg:

- ``198.168.0.0/24`` to allow the entire LAN.
- ``0.0.0.0/0`` to allow any address (useful for development / testing).

This value can be overridden per organization in the organization
change page. You can skip setting this option if you intend to set
it from organization change page for each organization.

.. image:: /images/freeradius_allowed_hosts.png
   :alt: Organization change page freeradius settings

.. code-block:: python

    OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS = ['127.0.0.1', '192.0.2.10', '192.168.0.0/24']

If this option and organization change page option are both
empty, then all freeradius API requests for the organization
will return ``403``.

.. _coa_enabled_setting:

``OPENWISP_RADIUS_COA_ENABLED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False```

If set to ``True``, openwisp-radius will update the NAS with the
user's current RADIUS attributes whenever the ``RadiusGroup`` of
user is changed. This allow enforcing of rate limits on active
RADIUS sessions without requiring users to re-authenticate. For
more details, :ref:`read the dedicated section for configuring
openwisp-radius and NAS for using CoA <change_of_authorization>`.

This can be overridden for each organization separately
via the organization radius settings section of the admin interface.

.. image:: /images/organization_coa_enabled.png
   :alt: CoA enabled

```RADCLIENT_ATTRIBUTE_DICTIONARIES```
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+--------------+----------+
| **type**:    | ``list`` |
+--------------+----------+
| **default**: | ``[]``   |
+--------------+----------+

List of absolute file paths of additional RADIUS dictionaries used
for RADIUS attribute mapping.

.. note::

    A `default dictionary <https://github.com/openwisp/openwisp-radius/blob/master/openwisp_radius/radclient/dictionary>`_
    is shipped with openwisp-radius. Any dictionary added using this setting
    will be used alongside the default dictionary. 

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

.. note::

    The numeric value represents the size of files in bytes.
    Setting this to ``None`` will mean there's no max size.

``OPENWISP_RADIUS_PRIVATE_STORAGE_INSTANCE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+--------------+-------------------------------------------------------------------------------------+
| **type**:    | ``str``                                                                             |
+--------------+-------------------------------------------------------------------------------------+
| **default**: |  ``openwisp_radius.private_storage.storage.private_file_system_storage``            |
+--------------+-------------------------------------------------------------------------------------+

Dotted path to an instance of any one of the storage classes in
`private_storage <https://github.com/edoburu/django-private-storage#django-private-storage>`_.
This instance is used for storing csv files of batch imports of users.

By default, an instance of ``private_storage.storage.files.PrivateFileSystemStorage``
is used.

.. _openwisp_radius_called_station_ids:

``OPENWISP_RADIUS_CALLED_STATION_IDS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``{}``

This setting allows to specify the parameters to connect to the different
OpenVPN management interfaces available for an organization. This setting is used by the
:ref:`convert_called_station_id <convert_called_station_id>` command.

It should contain configuration in following format:

.. code-block:: python

    OPENWISP_RADIUS_CALLED_STATION_IDS = {
        # UUID of the organization for which settings are being specified
        # In this example 'default'
        '<organization_uuid>': {
            'openvpn_config': [
                {
                    # Host address of OpenVPN management
                    'host': '<host>',
                    # Port of OpenVPN management interface. Defaults to 7505 (integer)
                    'port': 7506,
                    # Password of OpenVPN management interface (optional)
                    'password': '<management_interface_password>',
                }
            ],
            # List of CALLED STATION IDs that has to be converted,
            # These look like: 00:27:22:F3:FA:F1:gw1.openwisp.org
            'unconverted_ids': ['<called_station_id>'],
        }
    }

``OPENWISP_RADIUS_CONVERT_CALLED_STATION_ON_CREATE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

If set to ``True``, "Called Station ID" of a RADIUS session will be
converted (as per configuration defined in :ref:`OPENWISP_RADIUS_CALLED_STATION_IDS <openwisp_radius_called_station_ids>`)
just after the RADIUS session is created.

.. _openwisp_radius_openvpn_datetime_format:

``OPENWISP_RADIUS_OPENVPN_DATETIME_FORMAT``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``u'%a %b %d %H:%M:%S %Y'``

Specifies the datetime format of OpenVPN management status parser used by the
:ref:`convert_called_station_id <convert_called_station_id>`
command.

API and user token related settings
===================================

These settings control details related to the API and the radius user token.

``OPENWISP_RADIUS_API_URLCONF``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``None``

Changes the urlconf option of django urls to point the RADIUS API
urls to another installed module, example, ``myapp.urls``
(useful when you have a seperate API instance.)

``OPENWISP_RADIUS_API_BASEURL``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``/`` (points to same server)

If you have a seperate instance of openwisp-radius API on a
different domain, you can use this option to change the base of the image
download URL, this will enable you to point to your API server's domain,
example value: ``https://myradius.myapp.com``.

.. _openwisp_radius_api:

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

.. _openwisp_radius_api_authorize_reject:

``OPENWISP_RADIUS_API_AUTHORIZE_REJECT``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Indicates wether the :ref:`Authorize API view <authorize>` will return
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

.. _openwisp_radius_allowed_mobile_prefixes:

``OPENWISP_RADIUS_ALLOWED_MOBILE_PREFIXES``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``[]``

This setting is used to specify a list of international mobile prefixes which should
be allowed to register into the system via the :ref:`user registration API <user_registration>`.

That is, only users with phone numbers using the specified international prefixes will
be allowed to register.

Leaving this unset or setting it to an empty list (``[]``) will effectively allow
any international mobile prefix to register (which is the default setting).

For example:

.. code-block:: python

    OPENWISP_RADIUS_ALLOWED_MOBILE_PREFIXES = ['+44', '+237']

Using the setting above will only allow phone numbers from the UK (``+44``)
or Cameroon (``+237``).

.. note::

    This setting is applicable only for organizations
    which have :ref:`enabled the SMS verification option
    <openwisp_radius_sms_verification_enabled>`.

.. _openwisp_radius_optional_registration_fields:

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
:ref:`User Registration API <user_registration>`.

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

.. note::

    This setting can be overridden for each organization in the
    organization admin page, the setting implementation is left
    for backward compatibility but may be deprecated in the future.

**Default**:

.. code-block:: python

    {
        '__all__': 'https://{site}/{organization}/password/reset/confirm/{uid}/{token}'
    }

A dictionary representing the frontend URLs through which end users can complete
the password reset operation.

The frontend could be `openwisp-wifi-login-pages <https://github.com/openwisp/openwisp-wifi-login-pages>`_
or another in-house captive page solution.

Keys of the dictionary must be either UUID of organizations or ``__all__``, which is the fallback URL
that will be used in case there's no customized URL for a specific organization.

The password reset URL must contain the "{token}" and "{uid}" placeholders.

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
        '__all__': 'https://login.wifiservice.com/{organization}/password/reset/confirm/{uid}/{token}'
    }

.. _openwisp_radius_registration_api_enabled:

``OPENWISP_RADIUS_REGISTRATION_API_ENABLED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``True``

Indicates whether the API registration view is enabled or not.
When this setting is disabled (i.e. ``False``), the registration API view is disabled.

**This setting can be overridden in individual organizations
via the admin interface**, by going to *Organizations*
then edit a specific organization and scroll down to
*"Organization RADIUS settings"*, as shown in the screenshot below.

.. image:: /images/organization_registration_setting.png
   :alt: Organization RADIUS settings

.. note::

    We recommend using the override via the admin interface only when there
    are special organizations which need a different configuration, otherwise,
    if all the organization use the same configuration, we recommend
    changing the global setting.

.. _openwisp_radius_sms_verification_enabled:

``OPENWISP_RADIUS_SMS_VERIFICATION_ENABLED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

.. note::

    If you're looking for instructions on how to configure SMS sending,
    see :ref:`SMS Token Related Settings <sms_token_related_settings>`.

If :ref:`Identity verification is required <openwisp_radius_needs_identity_verification>`,
this setting indicates whether users who sign up should be required to
verify their mobile phone number via SMS.

This can be overridden for each organization separately
via the organization radius settings section of the admin interface.

.. image:: /images/organization_sms_verification_setting.png
   :alt: SMS verification enabled

.. _openwisp_radius_needs_identity_verification:

``OPENWISP_RADIUS_NEEDS_IDENTITY_VERIFICATION``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Indicates whether organizations require a user to be verified in order to login.
This can be overridden globally or for each organization separately via the admin
interface.

If this is enabled, each registered user should be verified using a verification method.
The following choices are available by default:

- ``''`` (empty string): unspecified
- ``manual``: manually created
- ``email``: Email (No Identity Verification)
- ``mobile_phone``: Mobile phone number
  :ref:`verification via SMS <openwisp_radius_sms_verification_enabled>`
- ``social_login``: :ref:`social login feature <social_login>`

.. note::

    Of the methods listed above, ``mobile_phone`` is generally
    accepted as a legal and valid form of indirect identity verification
    in those countries who require to provide
    a valid ID document before buying a SIM card.

    Organizations which are required by law to identify their users
    before allowing them to access the network (eg: ISPs) can restrict
    users to register only through this method and can configure the system
    to only :ref:`allow international mobile prefixes <openwisp_radius_allowed_mobile_prefixes>`
    of countries which require a valid ID document to buy a SIM card.

    **Disclaimer:** these are just suggestions on possible configurations
    of OpenWISP RADIUS and must not be considered as legal advice.

Adding support for more registration/verification methods
#########################################################

For those who need to implement additional registration and identity
verification methods, such as supporting a National ID card, new methods
can be added or an existing method can be removed using
the ``register_registration_method``
and ``unregister_registration_method`` functions respectively.

For example:

.. code-block:: python

    from openwisp_radius.registration import (
        register_registration_method,
        unregister_registration_method,
    )

    # Enable registering via national digital ID
    register_registration_method('national_id', 'National Digital ID')

    # Remove mobile verification method
    unregister_registration_method('mobile_phone')

.. note::

    Both functions will fail if a specific registration method
    is already registered or unregistered, unless the keyword argument
    ``fail_loud`` is passed as ``False`` (this useful when working with
    additional registration methods which are supported by multiple
    custom modules).

    Pass ``strong_identity`` as ``True`` to to indicate that users who
    register using that method have indirectly verified their identity
    (eg:  :ref:`SMS verification
    <openwisp_radius_sms_verification_enabled>`,
    credit card, national ID card, etc).

.. warning::

    If you need to implement a registration method that needs to grant limited
    internet access to unverified users so they can complete their
    verification process online on other websites which cannot be predicted
    and hence cannot be added to the walled garden, you can pass
    ``authorize_unverified=True`` to the ``register_registration_method``
    function.

    This is needed to implement payment flows in which users insert
    a specific 3D secure code in the website of their bank.
    Keep in mind that you should create a specific limited radius group
    for these unverified users.

    Payment flows and credit/debit card verification are fully implemented
    in **OpenWISP Subscriptions**, a premium module available only to
    customers of the
    :ref:`commercial support offering of OpenWISP <support>`.

Email related settings
======================

Emails can be sent to users whose usernames or passwords have been auto-generated.
The content of these emails can be customized with the settings explained below.

.. _openwisp_radius_batch_mail_subject:

``OPENWISP_RADIUS_BATCH_MAIL_SUBJECT``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``Credentials``

It is the subject of the mail to be sent to the users. Eg: ``Login Credentials``.

.. _openwisp_radius_batch_mail_message:

``OPENWISP_RADIUS_BATCH_MAIL_MESSAGE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``username: {}, password: {}``

The message should be a string in the format ``Your username is {} and password is {}``.

The text could be anything but should have the format string operator ``{}`` for
``.format`` operations to work.

.. _openwisp_radius_batch_mail_sender:

``OPENWISP_RADIUS_BATCH_MAIL_SENDER``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``settings.DEFAULT_FROM_EMAIL``

It is the sender email which is also to be configured in the SMTP settings.
The default sender email is a common setting from the
`Django core settings  <https://docs.djangoproject.com/en/dev/ref/settings/#default-from-email>`_
under ``DEFAULT_FROM_EMAIL``.
Currently, ``DEFAULT_FROM_EMAIL`` is set to to ``webmaster@localhost``.

.. _counter_related_settings:

Counter related settings
========================

.. _counters_setting:

``OPENWISP_RADIUS_COUNTERS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: depends on the database backend in use,
see :ref:`counters` to find out what are the default counters enabled.

It's a list of strings, each representing the python path to a counter class.

It may be set to an empty list or tuple to disable the counter feature, eg:

.. code-block:: python

    OPENWISP_RADIUS_COUNTERS = []

If custom counters have been implemented, this setting should be changed
to include the new classes, eg:

.. code-block:: python

    OPENWISP_RADIUS_COUNTERS = [
        # default counters for PostgreSQL, may be removed if not needed
        'openwisp_radius.counters.postgresql.daily_counter.DailyCounter',
        'openwisp_radius.counters.postgresql.daily_traffic_counter.DailyTrafficCounter',
        # custom counters
        'myproject.counters.CustomCounter1',
        'myproject.counters.CustomCounter2',
    ]

.. _traffic_counter_check_name:

``OPENWISP_RADIUS_TRAFFIC_COUNTER_CHECK_NAME``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``Max-Daily-Session-Traffic``

Used by :ref:`daily_traffic_counter`,
it indicates the check attribute which is looked for
in the database to find the maximum amount of daily traffic
which users having the default ``users`` radius group assigned can consume.

.. _traffic_counter_reply_name:

``OPENWISP_RADIUS_TRAFFIC_COUNTER_REPLY_NAME``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``ChilliSpot-Max-Total-Octets``

Used by :ref:`daily_traffic_counter`,
it indicates the reply attribute which is returned to the NAS
to indicate how much remaining traffic users
which users having the default ``users`` radius group assigned
can consume.

It should be changed according to the NAS software in use, for example,
if using PfSense, this setting should be set to ``pfSense-Max-Total-Octets``.

.. _social_login_settings:

Social Login related settings
=============================

The following settings are related to the :ref:`social login feature <social_login>`.

.. _openwisp_radius_social_registration_enabled:

``OPENWISP_RADIUS_SOCIAL_REGISTRATION_ENABLED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Indicates whether the registration using social applications
is enabled or not. When this setting is enabled (i.e. ``True``),
authentication using social applications is enabled for all organizations.

**This setting can be overridden in individual organizations
via the admin interface**, by going to *Organizations*
then edit a specific organization and scroll down to
*"Organization RADIUS settings"*, as shown in the screenshot below.

.. image:: /images/organization_social_login_setting.png
   :alt: Organization social login settings

.. note::

    We recommend using the override via the admin interface only when there
    are special organizations which need a different configuration, otherwise,
    if all the organization use the same configuration, we recommend
    changing the global setting.

.. _saml_settings:

SAML related settings
=====================

The following settings are related to the :ref:`SAML feature <saml_>`.

.. _openwisp_radius_saml_registration_enabled:

``OPENWISP_RADIUS_SAML_REGISTRATION_ENABLED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Indicates whether registration using SAML is enabled or not.
When this setting is enabled (i.e. ``True``),
authentication using SAML is enabled for all organizations.

**This setting can be overridden in individual organizations
via the admin interface**, by going to *Organizations*
then edit a specific organization and scroll down to
*"Organization RADIUS settings"*, as shown in the screenshot below.

.. image:: /images/organization_saml_setting.png
   :alt: Organization SAML settings

.. note::

    We recommend using the override via the admin interface only when there
    are special organizations which need a different configuration, otherwise,
    if all the organization use the same configuration, we recommend
    changing the global setting.

``OPENWISP_RADIUS_SAML_REGISTRATION_METHOD_LABEL``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``'Single Sign-On (SAML)'``

Sets the verbose name of SAML registration method.

``OPENWISP_RADIUS_SAML_IS_VERIFIED``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Setting this to ``True`` will automatically flag user accounts
created during SAML sign-in as verified users (``RegisteredUser.is_verified=True``).

This is useful when SAML identity providers can be trusted
to be legally valid identity verifiers.

.. _openwisp_radius_saml_updates_pre_existing_username:

``OPENWISP_RADIUS_SAML_UPDATES_PRE_EXISTING_USERNAME``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``False``

Allows updating username of a registered user with the value
received from SAML Identity Provider. Read the
:ref:`FAQs in SAML integration documentation <preventing_change_in_username_of_registered_user>`
for details.

.. _sms_token_related_settings:

SMS token related settings
==========================

These settings allow to control aspects and limitations of the SMS tokens
which are sent to users for the purpose of
:ref:`verifying their mobile phone number
<openwisp_radius_needs_identity_verification>`.

These settings are applicable only when
:ref:`SMS verification is enabled <openwisp_radius_sms_verification_enabled>`.

``SENDSMS_BACKEND``
~~~~~~~~~~~~~~~~~~~

This setting takes a python path which points to the `django-sendsms
<https://github.com/stefanfoulis/django-sendsms>`__
backend which will be used by the system to send SMS messages.

The list of supported SMS services can be seen in the source code of
`the django-sendsms backends
<https://github.com/stefanfoulis/django-sendsms/tree/main/sendsms/backends>`__.
Adding support for other SMS services can be done by subclassing
the ``BaseSmsBackend`` and implement the logic needed to talk to the
SMS service.

The value of this setting can point to any class on the python path,
so the backend doesn't have to be necessarily shipped in django-sendsms
but can be deployed in any other location.

``OPENWISP_RADIUS_SMS_TOKEN_DEFAULT_VALIDITY``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``30``

For how many minutes the SMS token is valid for.

``OPENWISP_RADIUS_SMS_TOKEN_LENGTH``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``6``

The length of the SMS token.

``OPENWISP_RADIUS_SMS_TOKEN_HASH_ALGORITHM``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``'sha256'``

The hashing algorithm used to generate the numeric code.

``OPENWISP_RADIUS_SMS_TOKEN_MAX_ATTEMPTS``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``5``

The max number of mistakes tolerated during verification,
after this amount of mistaken attempts, it won't be possible to
verify the token anymore and it will be necessary to request a new one.

``OPENWISP_RADIUS_SMS_TOKEN_MAX_USER_DAILY``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``5``

The max number of SMS tokens a single user can request within a day.

``OPENWISP_RADIUS_SMS_TOKEN_MAX_IP_DAILY``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``999``

The max number of tokens which can be requested from the same IP address
during the same day.

``OPENWISP_RADIUS_SMS_MESSAGE_TEMPLATE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``{organization} verification code: {code}``

The template used for sending verification code to users via SMS.

.. note::

    The template should always contain ``{code}`` placeholder.
    Otherwise, the sent SMS will not contain the verification code.

This value can be overridden per organization in the organization
change page. You can skip setting this option if you intend to set
it from organization change page for each organization. Keep in mind that
the default value is translated in other languages. If the value is
customized the translations will not work, so if you need this message
to be translated in different languages you should either not change the
default value or prepare the additional translations.
