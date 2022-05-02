Change log
==========

Version 1.0.0 [2022-04-18]
--------------------------

Features
~~~~~~~~

- Allowed to login via API with email or phone number
- Allowed freeradius authorize with email or phone number
- Allowed the usage of subnets in `OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS
  <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-freeradius-allowed-hosts>`_
- Made the fields containing personal data of users which are exposed in the registration API
  configurable (allowed, mandatory, disabled) via the
  `OPENWISP_RADIUS_OPTIONAL_REGISTRATION_FIELDS setting or the admin interface
  <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-optional-registration-fields>`_
- Allow to disable registration API via the
  `OPENWISP_RADIUS_REGISTRATION_API_ENABLED setting
  or the admin interface
  <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-registration-api-enabled>`_
- Added `throttling of API requests
  <https://openwisp-radius.readthedocs.io/en/latest/user/api.html#api-throttling>`_
- Added `OPENWISP_RADIUS_API_BASEURL setting
  <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-api-baseurl>`_
- Add identity verification feature, configurable via the
  `OPENWISP_RADIUS_NEEDS_IDENTITY_VERIFICATION or via admin interface
  <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-needs-identity-verification>`_
- Added utilities for implementing
  `new registration and identity verification methods
  <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#adding-support-for-more-registration-verification-methods>`_
- Added `captive portal mock views
  <https://openwisp-radius.readthedocs.io/en/latest/developer/captive_portal_mock.html>`_
  to ease development and debugging
- Add possibility to filter users by registration method in the admin interface
- Added SAML registration method to implement `captive portal authentication
  via Single Sign On (SSO) <https://openwisp-radius.readthedocs.io/en/latest/user/saml.html>`_
- Added management command and celery task to
  `delete unverified users
  <https://openwisp-radius.readthedocs.io/en/latest/user/management_commands.html#delete-unverified-users>`_
- Added translations of user facing API responses in Italian, German, Slovenian and Furlan
- Added `Convert RADIUS accounting CALLED-STATION-ID feature
  <https://openwisp-radius.readthedocs.io/en/latest/user/management_commands.html#convert-called-station-id>`_,
  celery task and management command,
  with the possibility of triggering it on accounting creation
  (see `OPENWISP_RADIUS_CONVERT_CALLED_STATION_ON_CREATE
  <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-convert-called-station-on-create>`_)
- Added an `equivalent of the FreeRADIUS sqlcounter feature to the REST API
  <https://openwisp-radius.readthedocs.io/en/latest/user/enforcing_limits.html#how-limits-are-enforced-counters>`_
- Added emission of django signal to FreeRADIUS accounting view:
  `radius_accounting_success
  <https://openwisp-radius.readthedocs.io/en/latest/developer/signals.html#radius-accounting-success>`_
- Added possibility to send email to the user an they start
  a new radius accounting session
- Added organization level settings and related admin interface functionality
  to enable/disable SAML and social login:

  - `OPENWISP_RADIUS_SAML_REGISTRATION_ENABLED
    <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-saml-registration-enabled>`_
  - `OPENWISP_RADIUS_SOCIAL_REGISTRATION_ENABLED
    <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-social-registration-enabled>`_

- Added setting to avoid updating username from SAML:
  `OPENWISP_RADIUS_SAML_UPDATES_PRE_EXISTING_USERNAME
  <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-saml-updates-pre-existing-username>`_

Changes
~~~~~~~

Backward incompatible changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- Updated prefixes of REST API URLs:

  - API endpoints dedicated to FreeRADIUS have moved to ``/api/v1/freeradius/``
  - the rest of the API endpoints have moved to ``/api/v1/radius/``

- Allowed ``username`` and ``phone_number`` in password reset API,
  the endpoint now accepts the "input" parameter instead of "email"
- Removed customizations for checks and password hashing because
  they are unmaintained, any user needing these customizations is
  advised to implement them as a third party app
- Improved REST API to change password:
  inherited ``PasswordChangeView`` of openwisp-users to add support for
  the current-password field in password change view

Dependencies
^^^^^^^^^^^^

- Added support for Django 3.2 and 4.0
- Dropped support for Django 2.2
- Upgraded celery to 5.2.x
- Updated and tested Django REST Framework to 3.13.0
- Added support for Python 3.8, 3.9
- Removed support for Python 3.6

Other changes
^^^^^^^^^^^^^

- Moved AccountingView to freeradius endpoints
- Relaxed default values for the
  `SMS token settings <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#sms-token-related-settings>`_
- Switched to new navigation menu and new OpenWISP theme
- Allowed users to sign up to multiple organizations
- Update username when phone number is changed if username is equal to the phone number
- Update stop time and termination to ``None`` if ``status_type`` is ``Interim-Update``
- Send password reset emails using HTML theme:
  leverage the new `openwisp-utils send_email function
  <https://github.com/openwisp/openwisp-utils#openwisp-utils-admin-theme-email-send-email>`_
  to send an HTML version
  of the reset password email based on the configurable email HTML theme of OpenWISP
- Save the user preferred language in obtain and validate token views
- Added validation check to prevent invalid username in batch user creation
- Allowed to set the
  `Password Reset URL setting
  <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-password-reset-urls>`_
  via the admin interface
- Added soft limits to celery tasks for background operations
- Generalized the implementation of the fallback model fields which allow
  overriding general settings for each organization

Bugfixes
~~~~~~~~

- Fixed login template of openwisp-admin-theme
- Fixed swagger API docs collision with openwisp-users
- Ensured each user can be member of a group only once
- Radius check and reply should check for organization membership
- ``ValidateAuthTokenView``: show ``phone_number`` as ``null`` if ``None``
- Freeradius API: properly handle interaction between multiple orgs:
  an user trying to authorize using the authorization data of an
  org for which they are not member of must be rejected
- Fixed radius user group creation with multiple orgs
- Added validation of phone number uniqueness in the registration API
- Fixed issues with translatable strings:

  - we don't translate log lines anymore because these won't be shown
    to end users
  - ``gettext`` does not work with fstrings,
    therefore the use of ``str.format()`` has been restored
  - improved some user facing strings

- Fixed Accounting-On and Accounting-Of accounting requests with blank usernames
- Delete any cached radius token key on phone number change
- Fixed handling of interim-updates for closed sessions:
  added handling of "Interim-Updates" for RadiusAccounting sessions
  that are closed by OpenWISP when user logs into another organization
- Flag user as verified in batch user creation
- Added validation which prevents the creation of duplicated
  check/reply attributes

Version 0.2.1 [2020-12-14]
--------------------------

Changes
~~~~~~~

- Increased openwisp-users and openwisp-utils versions to be
  consistent with the `OpenWISP 2020-12 release
  <https://github.com/openwisp/ansible-openwisp2/releases/tag/0.12.0>`_
- Increased dj-rest-auth to 2.1.2 and weasyprint to 52

Version 0.2.0 [2020-12-11]
--------------------------

Features
~~~~~~~~

- Changing the phone number via the API now keeps track of previous phone numbers
  used by the user to comply with ISP legal requirements

Changes
~~~~~~~

- Obtain Auth Token View API endpoint: added ``is_active`` attribute to response
- Obtain Auth Token View API endpoint: if the user attempting to authenticate
  is inactive, the API will return HTTP status code 401 along with the auth token
  and ``is_active`` attribute
- Validate Auth Token View API endpoint: added ``is_active``, ``phone_number``
  and ``email`` to response data
- When changing phone number, user is flagged as inactive only after
  the phone token is created and sent successfully
- All API endpoints related to phone token and SMS sending are now
  disabled (return 403 HTTP response) if SMS verification not enabled
  at organization level

Bugfixes
~~~~~~~~

- Removed ``static()`` call from media assets
- Fixed password reset for inactive users
- Fixed default password reset URL value and added docs
- Documentation: fixed several broken internal links

Version 0.1.0 [2020-09-10]
--------------------------

- administration web interface
- support for freeradius 3.0
- multi-tenancy
- REST API
- integration with rlm_rest module of freeradius
- possibility of registering new users via API
- social login support
- mobile phone verification via SMS tokens
- possibility to import users from CSV files
- possibility to generate users for events
- management commands and/or celery tasks to perform
  clean up operations and periodic tasks
- possibility to extend the base classes and swap models
  to add custom functionality without changing the core code
