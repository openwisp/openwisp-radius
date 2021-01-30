Changelog
=========

Version 0.3.0 [unreleased]
--------------------------

Features
~~~~~~~~

- Allowed login via API with email or phone number
- Allowed freeradius authorize with email or phone number
- Allowed the usage of subnets in `OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS
  <https://openwisp-radius.readthedocs.io/en/latest/user/settings.html#openwisp-radius-freeradius-allowed-hosts>`_

Changes
~~~~~~~

N/A.

Bugfixes
~~~~~~~~

N/A.

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
