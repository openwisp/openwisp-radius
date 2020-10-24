Changelog
=========

Version 0.2.0 [unreleased]
--------------------------

Changes
~~~~~~~

- Obtain Auth Token View API endpoint: added ``is_active`` attribute to response
- Obtain Auth Token View API endpoint: if the user attempting to authenticate
  is inactive, the API will return HTTP status code 401 along with the auth token
  and ``is_active`` attribute

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
