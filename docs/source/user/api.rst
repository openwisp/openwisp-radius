=================
API Documentation
=================

.. contents:: **Table of Contents**:
   :backlinks: none
   :depth: 4

.. important::
    The REST API of openwisp-radius is enabled by default and may be turned off by
    setting `OPENWISP_RADIUS_API <./settings.html#openwisp-radius-api>`_ to ``False``.

Live documentation
******************

.. image:: /images/swagger_api.png
   :alt: Swagger API Documentation

A general live API documentation (following the OpenAPI specification) at ``/api/v1/docs/``.

Browsable web interface
***********************
.. image:: /images/drf_api_interface.png
   :alt: API Interface

Additionally, opening any of the endpoints `listed below <#list-of-endpoints>`_
directly in the browser will show the `browsable API interface of Django-REST-Framework
<https://www.django-rest-framework.org/topics/browsable-api/>`_,
which makes it even easier to find out the details of each endpoint.

FreeRADIUS API Endpoints
************************

The following section is dedicated to API endpoints that are designed
to be consumed by FreeRADIUS (`Authorize`_, `Post Auth`_, `Accounting`_).

.. important::
    These endpoints can be consumed only by hosts which have
    been added to the `freeradius allowed hosts list
    <./settings.html#openwisp-radius-freeradius-allowed-hosts>`_.

.. _freeradius_api_authentication:

FreeRADIUS API Authentication
=============================

There are 3 different methods with which the FreeRADIUS API endpoints
can authenticate incoming requests and understand to which organization
these requests belong.

.. _radius_user_token:

Radius User Token
-----------------

This method relies on the presence of a special token which was obtained
by the user when authenticating via the
`Obtain Auth Token View <#login-obtain-user-auth-token>`_, this means
the user would have to log in through something like a web form first.

The flow works as follows:

1. the user enters credentials in a login form belonging to a specific organization
   and submits, the credentials are then sent to the `Obtain Auth Token View <#login-obtain-user-auth-token>`_;
2. if credentials are correct, a **radius user token** associated to the user
   and organization is created and returned in the response;
3. the login page or app must then initiate the HTTP request to the web server
   of the captive portal,
   (the URL of the form action of the default captive login page)
   using the radius user token as password, example:

.. code-block:: text

    curl -X POST http://captive.projcect.com:8005/index.php?zone=myorg \
         -d "auth_user=<username>&auth_pass=<radius_token>"

This method is recommended if you are using multiple organizations
in the same OpenWISP instance.

.. note::
    By default, ``<radius_token>`` is valid for authentication for one
    request only and a new ``<radius_token>`` needs to be `obtained for
    each request <#login-obtain-user-auth-token>`_.
    However, if `OPENWISP_RADIUS_DISPOSABLE_RADIUS_USER_TOKEN
    <./settings.html#openwisp-radius-disposable-radius-user-token>`_
    is set to ``False``, the ``<radius_token>`` is valid for authentication
    as long as freeradius accounting ``Stop`` request is not sent
    or the token is not deleted.

.. warning::
    If you are using Radius User token method, keep in mind that one
    user account can only authenticate with one organization
    at a time, i.e a single user account cannot consume
    services from multiple organizations simultaneously.

Bearer token
------------

This other method allows to use the system without the need for a user
to obtain a token first, the drawback is that one FreeRADIUS site has to
be configured for each organization, the authorization credentials for
the specific organization is sent in each request,
see :ref:`freeradius_site` for more information on
the FreeRADIUS site configuration.

The (`Organization UUID and Organization RADIUS token
<#organization-uuid-token>`_) are sent in the authorization header of
the HTTP request in the form of a Bearer token, eg:

.. code-block:: text

      curl -X POST http://localhost:8000/api/v1/freeradius/authorize/ \
           -H "Authorization: Bearer <org-uuid> <token>" \
           -d "username=<username>&password=<password>"

This method is recommended if you are using only one organization
and you have no need nor intention of adding more organizations in the future.

Querystring
-----------

This method is identical to the previous one, but the credentials
are sent in querystring parameters, eg:

.. code-block:: text

      curl -X POST http://localhost:8000/api/v1/freeradius/authorize/?uuid=<org-uuid>&token=<token> \
           -d "username=<username>&password=<password>"

This method is not recommended for production usage, it should be
used for testing and debugging only
(because webservers can include the querystring parameters in their logs).

.. _organization_uuid_token:

Organization UUID & RADIUS API Token
------------------------------------

You can get (and set) the value of the OpenWISP RADIUS API token in the
organization configuration page on the OpenWISP dashboard
(select your organization in ``/admin/openwisp_users/organization/``):

.. image:: /images/token.png
   :alt: Organization Radius Token

.. note::
    It is highly recommended that you use a hard to guess value, longer than
    15 characters containing both letters and numbers.
    Eg: ``165f9a790787fc38e5cc12c1640db2300648d9a2``.

You will also need the UUID of your organization from the organization change page
(select your organization in ``/admin/openwisp_users/organization/``):

.. image:: /images/org_uuid.png
   :alt: Organization UUID

Requests authorizing with `bearer-token <#bearer-token>`_ or `querystring
<#querystring>`_ method **must** contain organization UUID & token. If the
tokens are missing or invalid, the request will receive a ``403`` HTTP error.

For information on how to configure FreeRADIUS to send the bearer tokens, see
:ref:`freeradius_site`.

API Throttling
==============

To override the default API throttling settings, add the following to your ``settings.py`` file:

.. code-block:: python

    REST_FRAMEWORK = {
        'DEFAULT_THROTTLE_CLASSES': [
            'rest_framework.throttling.ScopedRateThrottle',
        ],
        'DEFAULT_THROTTLE_RATES': {
            # None by default
            'authorize': None,
            'postauth': None,
            'accounting': None,
            'obtain_auth_token': None,
            'validate_auth_token': None,
            'create_phone_token': None,
            'validate_phone_token': None,
            # Relaxed throttling Policy
            'others': '400/hour',
        },
    }

The rate descriptions used in ``DEFAULT_THROTTLE_RATES`` may include
``second``, ``minute``, ``hour`` or ``day`` as the throttle period, setting it to ``None`` will result in no throttling.

List of Endpoints
=================

Authorize
---------

Use by FreeRADIUS to perform the ``authorization`` phase.

It's triggered when a user submits the form to login into the captive portal.
The captive portal has to be configured to send the password to freeradius in clear text
(will be encrypted with the freeradius shared secret, can be tunneled
via TLS for increased security if needed).

FreeRADIUS in turn will send the username and password via HTTPs to this endpoint.

Responds to only **POST**.

.. code-block:: text

    /api/v1/freeradius/authorize/

Example:

.. code-block:: text

    POST /api/v1/freeradius/authorize/ HTTP/1.1 username=testuser&password=testpassword

========    ===========================
Param       Description
========    ===========================
username    Username for the given user
password    Password for the given user
========    ===========================

If the authorization is successful, the API will return all group replies
related to the group with highest priority assigned to the user.

If the authorization is unsuccessful, the response body can either be empty
or it can contain an explicit rejection, depending on how the
`OPENWISP_RADIUS_API_AUTHORIZE_REJECT <settings.html#openwisp-radius-api-authorize-reject>`_
setting is configured.

Post Auth
---------

API endpoint designed to be used by FreeRADIUS ``postauth``.

Responds only to **POST**.

.. code-block:: text

    /api/v1/freeradius/postauth/

==================   ===================================
Param                Description
==================   ===================================
username             Username
password             Password (*)
reply                Radius reply received by freeradius
called_station_id    Called Station ID
calling_station_id   Calling Station ID
==================   ===================================

(*): the ``password`` is stored only on unsuccessful authorizations.

Returns an empty response body in order to instruct
FreeRADIUS to avoid processing the response body.

Accounting
----------

.. code-block:: text

    /api/v1/freeradius/accounting/

GET
~~~

Returns a list of accounting objects

.. code-block:: text

    GET /api/v1/freeradius/accounting/

.. code-block:: json

    [
      {
          "called_station_id": "00-27-22-F3-FA-F1:hostname",
          "nas_port_type": "Async",
          "groupname": null,
          "id": 1,
          "realm": "",
          "terminate_cause": "User_Request",
          "nas_ip_address": "172.16.64.91",
          "authentication": "RADIUS",
          "stop_time": null,
          "nas_port_id": "1",
          "service_type": "Login-User",
          "username": "admin",
          "update_time": null,
          "connection_info_stop": null,
          "start_time": "2018-03-10T14:44:17.234035+01:00",
          "output_octets": 1513075509,
          "calling_station_id": "5c:7d:c1:72:a7:3b",
          "input_octets": 9900909,
          "interval": null,
          "session_time": 261,
          "session_id": "35000006",
          "connection_info_start": null,
          "framed_protocol": "test",
          "framed_ip_address": "127.0.0.1",
          "unique_id": "75058e50"
      }
    ]

POST
~~~~

Add or update accounting information (start, interim-update, stop);
does not return any JSON response so that freeradius will avoid
processing the response without generating warnings

=====================     ======================
Param                     Description
=====================     ======================
session_id                Session ID
unique_id                 Accounting unique ID
username                  Username
groupname                 Group name
realm                     Realm
nas_ip_address            NAS IP address
nas_port_id               NAS port ID
nas_port_type             NAS port type
start_time                Start time
update_time               Update time
stop_time                 Stop time
interval                  Interval
session_time              Session Time
authentication            Authentication
connection_info_start     Connection Info Start
connection_info_stop      Connection Info Stop
input_octets              Input Octets
output_octets             Output Octets
called_station_id         Called station ID
calling_station_id        Calling station ID
terminate_cause           Termination Cause
service_type              Service Type
framed_protocol           Framed protocol
framed_ip_address         framed IP address
=====================     ======================

Pagination
++++++++++

Pagination is provided using a Link header pagination. Check `here for more information about
traversing with pagination <https://developer.github.com/v3/guides/traversing-with-pagination/>`_.

.. code-block:: text

    {
      ....
      ....
      link: <http://testserver/api/v1/freeradius/accounting/?page=2&page_size=1>; rel=\"next\",
            <http://testserver/api/v1/freeradius/accounting/?page=3&page_size=1>; rel=\"last\"
      ....
      ....
    }

.. note::
    Default page size is 10, which can be overridden using
    the `page_size` parameter.

Filters
+++++++

The JSON objects returned using the GET endpoint can be filtered/queried using specific parameters.

==================  ====================================
Filter Parameters   Description
==================  ====================================
username            Username
called_station_id   Called Station ID
calling_station_id  Calling Station ID
start_time          Start time (greater or equal to)
stop_time           Stop time (less or equal to)
is_open             If stop_time is null
==================  ====================================

User API Endpoints
******************

These API endpoints are designed to be used by users
(eg: creating an account, changing their password,
obtaining access tokens, validating their phone number, etc.).

.. note::
  The API endpoints described below do not require the
  `Organization API Token <#organization-api-token>`_
  described in the beginning of this document.

Some endpoints require the sending of the user API access
token sent in the form of a "Bearer Token", example:

.. code-block:: shell

    curl -H "Authorization: Bearer <user-token>" \
         'http://localhost:8000/api/v1/radius/organization/default/account/session/'

List of Endpoints
=================

User Registration
-----------------

.. important::

    This endpoint is enabled by default but can be disabled either
    via a `global setting or from the admin interface
    <settings.html#openwisp-radius-registration-api-enabled>`_.

.. code-block:: text

  /api/v1/radius/organization/<organization-slug>/account/

Responds only to **POST**.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
username           string
phone_number       string (\*)
email              string
password1          string
password2          string
first_name         string (\*\*)
last_name          string (\*\*)
birth_date         string (\*\*)
location           string (\*\*)
method             string (\*\*\*)
===============    ===============================

(\*) ``phone_number`` is required only when the organization has enabled
SMS verification in its "Organization RADIUS Settings".

(\*\*) ``first_name``, ``last_name``, ``birth_date`` and ``location``
are optional fields which are disabled by default to make the registration
simple, but can be `enabled through configuration <./settings.html#openwisp-radius-optional-registration-fields>`_.

(\*\*) ``method`` must be one of the available
`registration/verification methods <./settings.html#openwisp-radius-needs-identity-verification>`_;
if identity verification is disabled for a particular org, an empty string
will be acceptable.

Registering to Multiple Organizations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An **HTTP 409** response will be returned if an existing user tries to register
on a URL of a different organization (because the account already exists).
The response will contain a list of organizations with which the user has already
registered to the system which may be shown to the user in the UI. E.g.:

.. code-block:: json


    {
        "details": "A user like the one being registered already exists.",
        "organizations":[
            {"slug":"default","name":"default"}
        ]
    }

The existing user can register with a new organization using the
`login <#login-obtain-user-auth-token>`_ endpoint. The user will also get
membership of the new organization only if the organization has
`user registration enabled <settings.html#openwisp-radius-registration-api-enabled>`_.

Reset password
--------------

This is the classic "password forgotten recovery feature" which
sends a reset password token to the email of the user.

.. code-block:: text

    /api/v1/radius/organization/<organization-slug>/account/password/reset/

Responds only to **POST**.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
email              string
===============    ===============================

Confirm reset password
----------------------

Allows users to confirm their reset password after having it requested
via the `Reset password <#reset-password>`_ endpoint.

.. code-block:: text

    /api/v1/radius/organization/<organization-slug>/account/password/reset/confirm/

Responds only to **POST**.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
new_password1      string
new_password2      string
uid                string
token              string
===============    ===============================

Change password
---------------

**Requires the user auth token (Bearer Token)**.

Allows users to change their password after using the
`Reset password <#reset-password>`_ endpoint.

.. code-block:: text

    /api/v1/radius/organization/<organization-slug>/account/password/change/

Responds only to **POST**.

Parameters:

================   ===============================
Param              Description
================   ===============================
current_password   string
new_password       string
confirm_password   string
================   ===============================

Login (Obtain User Auth Token)
------------------------------

.. code-block:: text

    /api/v1/radius/organization/<organization-slug>/account/token/

Responds only to **POST**.

Returns:

- ``radius_user_token``: the user radius token, which can be used to authenticate
  the user in the captive portal by sending it in place of the user password
  (it will be passed to freeradius which in turn will send it to the
  `authorize API endpoint <#authorize>`_ which will recognize the token as
  the user passsword)
- ``key``: the user API access token, which will be needed to authenticate the user to
  eventual subsequent API requests (eg: change password)
- ``is_active`` if it's ``false`` it means the user has been banned
- ``is_verified`` when identity verification is enabled, it indicates
  whether the user has completed an indirect identity verification
  process like confirming their mobile phone number
- ``method`` registration/verification method used by the user to register,
  eg: ``mobile_phone``, ``social_login``, etc.
- ``username``
- ``email``
- ``phone_number``
- ``first_name``
- ``last_name``
- ``birth_date``
- ``location``

If the user account is inactive or unverified the endpoint will send the data
anyway but using the HTTP status code 401, this way consumers can recognize
these users and trigger the appropriate response needed (eg: reject them
or initiate account verification).

If an existing user account tries to authenticate to an organization of which
they're not member of, then they would be automatically added as members
(if registration is enabled for that org). Please refer to
`"Registering to Multiple Organizations" <#registering-to-multiple-organizations>`_.

This endpoint updates the user language preference field according
to the ``Accept-Language`` HTTP header.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
username           string
password           string
===============    ===============================

Validate user auth token
------------------------

Used to check whether the auth token of a user is valid or not.

Return also the radius user token and username in the response.

.. code-block:: text

    /api/v1/radius/organization/<organization-slug>/account/token/validate/

Responds only to **POST**.

Parameters:

=================  ===============================
Param              Description
=================  ===============================
token              the rest auth token to validate
=================  ===============================

The user information is returned in the response (similarly to
`Obtain User Auth Token <#login-obtain-user-auth-token>`__),
along with the following additional parameter:

- ``response_code``: string indicating whether the result is successful or not,
  to be used for translation.

This endpoint updates the user language preference field according
to the ``Accept-Language`` HTTP header.

User Radius Sessions
--------------------

**Requires the user auth token (Bearer Token)**.

Returns the radius sessions of the logged-in user and the organization specified
in the URL.

.. code-block:: text

    /api/v1/radius/organization/<organization-slug>/account/session/

Responds only to **GET**.

Create SMS token
----------------

**Requires the user auth token (Bearer Token)**.

Used for SMS verification, sends a code via SMS to the phone number of the user.

.. code-block:: text

    /api/v1/radius/organization/<organization-slug>/account/phone/token/

Responds only to **POST**.

No parameters required.

Verify/Validate SMS token
-------------------------

**Requires the user auth token (Bearer Token)**.

Used for SMS verification, allows users to validate the code they receive via SMS.

.. code-block:: text

    /api/v1/radius/organization/<organization-slug>/account/phone/verify/

Responds only to **POST**.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
code                string
===============    ===============================

Change phone number
-------------------

**Requires the user auth token (Bearer Token)**.

Allows users to change their phone number,
will flag the user as inactive and send them a verification code via SMS.
The phone number of the user is updated only after this verification code
has been `validated <#verify-validate-sms-token>`_.

.. code-block:: text

    /api/v1/radius/organization/<organization-slug>/account/phone/change/

Responds only to **POST**.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
phone_number       string
===============    ===============================

Batch user creation
-------------------

This API endpoint allows to use the features described in
:doc:`/user/importing_users` and :doc:`/user/generating_users`.

.. code-block:: text

    /api/v1/radius/batch/

.. note::
  This API endpoint allows to use the features described in :doc:`/user/importing_users`
  and :doc:`/user/generating_users`.

Responds only to **POST**, used to save a ``RadiusBatch`` instance.

It is possible to generate the users of the ``RadiusBatch`` with two different strategies: csv or prefix.

The csv method needs the following parameters:

=================  =================================
Param              Description
=================  =================================
name               Name of the operation
strategy           csv
csvfile            file with the users
expiration_date    date of expiration of the users
organization_slug  slug of organization of the users
=================  =================================

These others are for the prefix method:

=================  ==================================
Param              Description
=================  ==================================
name               name of the operation
strategy           prefix
prefix             prefix for the generation of users
number_of_users    number of users
expiration_date    date of expiration of the users
organization_slug  slug of organization of the users
=================  ==================================

When using this strategy, in the response you can find the field
``user_credentials`` containing the list of users created
(example: ``[['username', 'password'], ['sample_user', 'BBuOb5sN']]``)
and the field ``pdf_link`` which can be used to download a PDF file
containing the user credentials.
