Change log
==========

Version 1.1.0 [2024-11-21]
--------------------------

Features
~~~~~~~~

- Added integration with `OpenWISP Monitoring
  <https://openwisp.io/docs/dev/radius/user/radius_monitoring.html>`_ to
  collect and visualize metrics for user-signups and RADIUS traffic.
- Added support for `Change of Authorization (CoA)
  <https://openwisp.io/docs/dev/radius/user/change_of_authorization.html>`_.
- Added `MonthlyTrafficCounter
  <https://openwisp.io/docs/dev/radius/user/enforcing_limits.html#monthlytrafficcounter>`_
  and `MonthlySubscriptionTrafficCounter
  <https://openwisp.io/docs/dev/radius/user/enforcing_limits.html#monthlysubscriptiontrafficcounter>`_.
- Added API endpoint to fetch user's latest PhoneToken status.
- Added `OPENWISP_RADIUS_SMS_COOLDOWN
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-sms-cooldown>`_
  to configure cooldown time for requesting a new PhoneToken.
- Extended ``OPENWISP_USERS_EXPORT_USERS_COMMAND_CONFIG`` to include
  registration method and verification status.
- Added MAC address authentication for roaming users.
- Added `OPENWISP_RADIUS_SMS_MESSAGE_TEMPLATE
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-sms-message-template>`_
  setting to customize SMS messages.
- Added `OPENWISP_RADIUS_USER_ADMIN_RADIUSTOKEN_INLINE
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-user-admin-radiustoken-inline>`_
  setting to display RadiusTokenInline in UserAdmin.
- Added `OPENWISP_RADIUS_UNVERIFY_INACTIVE_USERS
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-unverify-inactive-users>`_
  setting to unverify users after a defined period of inactivity.
- Added `OPENWISP_RADIUS_DELETE_INACTIVE_USERS
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-delete-inactive-users>`_
  setting to delete inactive users after a specified period.
- Added API endpoint to return user's RADIUS usage.
- Supported password expiration feature from openwisp-users.
- Added initial support for Gigaword RADIUS attributes.
- Added ``LoginAdditionalInfoView`` to collection additional user details
  in SAML sign-up flow.
- Added autocomplete support for filters in the admin interface.

Changes
~~~~~~~

Backward incompatible changes
+++++++++++++++++++++++++++++

- Renamed ``delete_old_users`` command to
  ``delete_old_radiusbatch_users``.
- The `OPENWISP_RADIUS_BATCH_DELETE_EXPIRED
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-batch-delete-expired>`_
  setting now expects days instead of months.

Deprecation warnings
++++++++++++++++++++

- Using the ``default`` key in ``OPENWISP_RADIUS_PASSWORD_RESET_URLS`` is
  deprecated. Use ``__all__`` instead.
- Using organization slugs for key in
  ``OPENWISP_RADIUS_CALLED_STATION_IDS`` are deprecated. Use organization
  IDs instead.
- In ``delete_old_radiusbatch_users`` management command, the
  ``--older-than-months`` option is deprecated. Use ``--older-than-days``
  instead.

Dependencies
++++++++++++

- Bumped ``weasyprint~=59.0``.
- Bumped ``pydyf~=0.10.0``.
- Bumped ``dj-rest-auth~=6.0.0``.
- Bumped ``openwisp-utils[rest,celery]~=1.1.1``.
- Bumped ``openwisp-users~=1.1.0``.
- Bumped ``django-private-storage~=3.1.0``.
- Bumped ``django-ipware~=5.0.0``.
- Bumped ``djangosaml2~=1.9.2``.
- Added support for Django ``4.1.x`` and ``4.2.x``.
- Added support for Python ``3.10``.
- Dropped support for Python ``3.7``.
- Dropped support for Django ``3.0.x`` and ``3.1.x``.

Other changes
+++++++++++++

- The ``cleanup_stale_radacct`` management command now uses the session's
  ``update_time`` to determine staleness, falling back to ``start_time``
  if ``update_time`` is unavailable.
- Stopped sending login email notifications when accounting framed
  protocol is ``PPP``.
- Send login emails only to users with verified email addresses.
- Grouped SMS features in the organization admin.
- Allowed counter's check method to return ``None`` to prevent adding a
  reply to the response.
- The email received from the IdP in SAML registration will be flagged as
  verified.

Bugfixes
~~~~~~~~

- Fixed validation for organization's password reset URLs.
- Fixed saving ``RadiusCheck`` / ``RadiusReply`` objects without an
  organization returning a 500 HTTP response.
- Fixed handling of accounting stop requests with empty octets.
- Prevented user registration with landline numbers.
- Ignored `IntegrityError` on duplicate accounting start requests.
- Removed default values from fallback fields.
- User need to have required model permissions to perform admin actions.

Version 1.0.2 [2022-12-05]
--------------------------

Bugfixes
~~~~~~~~

- Made private storage backend configurable
- Updated API views to use ``filterset_class`` instead of ``filter_class``
  (required by ``django-filter==22.1``)
- Fixed organization cache bug in SAML ACS view: A forceful update of the
  user's organization cache is done before performing post-login
  operations to avoid issues occurring due to outdated cache.
- Added missing Furlan translation for sesame link validity
- Use storage backend method for deleting ``RadiusBatch.csvfile``: The
  previous implementation used the "os" module for deleting resisdual csv
  files. This causes issues when the project uses a file storage backend
  other than based on file system.
- Added error handling in RadiusBatch admin change view: Accessing admin
  change view of a non-existent RadiusBatch object resulted in Server
  Error 500 because the ``DoesNotExist`` conditioned was not handled.
- Load image using ``static()`` in RegisteredUserInline.get_is_verified
- Use ``path`` URL kwarg in "serve_private_file" URL pattern
- Honor DISPOSABLE_RADIUS_USER_TOKEN in accounting stop API view: The
  accounting stop REST API operation was not taking into account the
  OPENWISP_RADIUS_DISPOSABLE_RADIUS_USER_TOKEN setting when disabling the
  auth capability of the radius token.

Version 1.0.1 [2022-05-10]
--------------------------

Bugfixes
~~~~~~~~

- Fixed a bug in the organization radius settings form which was causing
  it to not display some default values correctly
- Fixed a bug in allowed mobile prefix implementation: the implementation
  was joining the globally allowed prefixes and the prefixes allowed at
  org level, with the result that disabling a prefix at org level was not
  possible
- Called-station-ID command: log with warning instead of ``warn`` or
  ``error``: - warn > warning (warn is deprecated) - use warning instead
  of errors for more temporary connection issues cases

Version 1.0.0 [2022-04-18]
--------------------------

Features
~~~~~~~~

- Allowed to login via API with email or phone number
- Allowed freeradius authorize with email or phone number
- Allowed the usage of subnets in
  `OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-freeradius-allowed-hosts>`_
- Made the fields containing personal data of users which are exposed in
  the registration API configurable (allowed, mandatory, disabled) via the
  `OPENWISP_RADIUS_OPTIONAL_REGISTRATION_FIELDS setting or the admin
  interface
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-optional-registration-fields>`_
- Allow to disable registration API via the
  `OPENWISP_RADIUS_REGISTRATION_API_ENABLED setting or the admin interface
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-registration-api-enabled>`_
- Added `throttling of API requests
  <https://openwisp.io/docs/dev/radius/user/api.html#api-throttling>`_
- Added `OPENWISP_RADIUS_API_BASEURL setting
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-api-baseurl>`_
- Add identity verification feature, configurable via the
  `OPENWISP_RADIUS_NEEDS_IDENTITY_VERIFICATION or via admin interface
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-needs-identity-verification>`_
- Added utilities for implementing `new registration and identity
  verification methods
  <https://openwisp.io/docs/dev/radius/user/settings.html#adding-support-for-more-registration-verification-methods>`_
- Added `captive portal mock views
  <https://openwisp.io/docs/dev/radius/developer/captive_portal_mock.html>`_
  to ease development and debugging
- Add possibility to filter users by registration method in the admin
  interface
- Added SAML registration method to implement `captive portal
  authentication via Single Sign On (SSO)
  <https://openwisp.io/docs/dev/radius/user/saml.html>`_
- Added management command and celery task to `delete unverified users
  <https://openwisp.io/docs/dev/radius/user/management_commands.html#delete-unverified-users>`_
- Added translations of user facing API responses in Italian, German,
  Slovenian and Furlan
- Added `Convert RADIUS accounting CALLED-STATION-ID feature
  <https://openwisp.io/docs/dev/radius/user/management_commands.html#convert-called-station-id>`_,
  celery task and management command, with the possibility of triggering
  it on accounting creation (see
  `OPENWISP_RADIUS_CONVERT_CALLED_STATION_ON_CREATE
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-convert-called-station-on-create>`_)
- Added an `equivalent of the FreeRADIUS sqlcounter feature to the REST
  API
  <https://openwisp.io/docs/dev/radius/user/enforcing_limits.html#how-limits-are-enforced-counters>`_
- Added emission of django signal to FreeRADIUS accounting view:
  `radius_accounting_success
  <https://openwisp.io/docs/dev/radius/developer/signals.html#radius-accounting-success>`_
- Added possibility to send email to the user an they start a new radius
  accounting session
- Added organization level settings and related admin interface
  functionality to enable/disable SAML and social login:

  - `OPENWISP_RADIUS_SAML_REGISTRATION_ENABLED
    <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-saml-registration-enabled>`_
  - `OPENWISP_RADIUS_SOCIAL_REGISTRATION_ENABLED
    <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-social-registration-enabled>`_

- Added setting to avoid updating username from SAML:
  `OPENWISP_RADIUS_SAML_UPDATES_PRE_EXISTING_USERNAME
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-saml-updates-pre-existing-username>`_

Changes
~~~~~~~

Backward incompatible changes
+++++++++++++++++++++++++++++

- Updated prefixes of REST API URLs:

  - API endpoints dedicated to FreeRADIUS have moved to
    ``/api/v1/freeradius/``
  - the rest of the API endpoints have moved to ``/api/v1/radius/``

- Allowed ``username`` and ``phone_number`` in password reset API, the
  endpoint now accepts the "input" parameter instead of "email"
- Removed customizations for checks and password hashing because they are
  unmaintained, any user needing these customizations is advised to
  implement them as a third party app
- Improved REST API to change password: inherited ``PasswordChangeView``
  of openwisp-users to add support for the current-password field in
  password change view

Dependencies
++++++++++++

- Added support for Django 3.2 and 4.0
- Dropped support for Django 2.2
- Upgraded celery to 5.2.x
- Updated and tested Django REST Framework to 3.13.0
- Added support for Python 3.8, 3.9
- Removed support for Python 3.6

Other changes
+++++++++++++

- Moved AccountingView to freeradius endpoints
- Relaxed default values for the `SMS token settings
  <https://openwisp.io/docs/dev/radius/user/settings.html#sms-token-related-settings>`_
- Switched to new navigation menu and new OpenWISP theme
- Allowed users to sign up to multiple organizations
- Update username when phone number is changed if username is equal to the
  phone number
- Update stop time and termination to ``None`` if ``status_type`` is
  ``Interim-Update``
- Send password reset emails using HTML theme: leverage the new
  `openwisp-utils send_email function
  <https://github.com/openwisp/openwisp-utils#openwisp-utils-admin-theme-email-send-email>`_
  to send an HTML version of the reset password email based on the
  configurable email HTML theme of OpenWISP
- Save the user preferred language in obtain and validate token views
- Added validation check to prevent invalid username in batch user
  creation
- Allowed to set the `Password Reset URL setting
  <https://openwisp.io/docs/dev/radius/user/settings.html#openwisp-radius-password-reset-urls>`_
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
- Freeradius API: properly handle interaction between multiple orgs: an
  user trying to authorize using the authorization data of an org for
  which they are not member of must be rejected
- Fixed radius user group creation with multiple orgs
- Added validation of phone number uniqueness in the registration API
- Fixed issues with translatable strings:

  - we don't translate log lines anymore because these won't be shown to
    end users
  - ``gettext`` does not work with fstrings, therefore the use of
    ``str.format()`` has been restored
  - improved some user facing strings

- Fixed Accounting-On and Accounting-Of accounting requests with blank
  usernames
- Delete any cached radius token key on phone number change
- Fixed handling of interim-updates for closed sessions: added handling of
  "Interim-Updates" for RadiusAccounting sessions that are closed by
  OpenWISP when user logs into another organization
- Flag user as verified in batch user creation
- Added validation which prevents the creation of duplicated check/reply
  attributes

Version 0.2.1 [2020-12-14]
--------------------------

Changes
~~~~~~~

- Increased openwisp-users and openwisp-utils versions to be consistent
  with the `OpenWISP 2020-12 release
  <https://github.com/openwisp/ansible-openwisp2/releases/tag/0.12.0>`_
- Increased dj-rest-auth to 2.1.2 and weasyprint to 52

Version 0.2.0 [2020-12-11]
--------------------------

Features
~~~~~~~~

- Changing the phone number via the API now keeps track of previous phone
  numbers used by the user to comply with ISP legal requirements

Changes
~~~~~~~

- Obtain Auth Token View API endpoint: added ``is_active`` attribute to
  response
- Obtain Auth Token View API endpoint: if the user attempting to
  authenticate is inactive, the API will return HTTP status code 401 along
  with the auth token and ``is_active`` attribute
- Validate Auth Token View API endpoint: added ``is_active``,
  ``phone_number`` and ``email`` to response data
- When changing phone number, user is flagged as inactive only after the
  phone token is created and sent successfully
- All API endpoints related to phone token and SMS sending are now
  disabled (return 403 HTTP response) if SMS verification not enabled at
  organization level

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
- management commands and/or celery tasks to perform clean up operations
  and periodic tasks
- possibility to extend the base classes and swap models to add custom
  functionality without changing the core code
