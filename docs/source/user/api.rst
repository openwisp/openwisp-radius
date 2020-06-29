=================
API Documentation
=================

.. contents:: **Table of Contents**:
   :backlinks: none
   :depth: 4

API endpoints for FreeRADIUS
############################

The following section is dedicated to API endpoints that are designed to be
consumed by FreeRADIUS.

Organization API Token
----------------------

Only requests containing the right API token and Organization UUID will able
to talk to the API endpoints consumed by freeradius
(`Authorize`_, `Post Auth`_, `Accounting`_).

You can get (and set) the value of the api token in the organization
configuration page on the OpenWISP dashboard
(select your organization in ``/admin/openwisp_users/organization/``):

.. image:: /images/token.png
   :alt: Organization Radius Token

It is highly recommended that you use a hard to guess value, longer than 15 characters
containing both letters and numbers. Eg: ``165f9a790787fc38e5cc12c1640db2300648d9a2``.

You will also need the UUID of your organization from the organization change page
(select your organization in ``/admin/openwisp_users/organization/``):

.. image:: /images/org_uuid.png
   :alt: Organization UUID

HTTP clients must send these tokens, either in the form of a `bearer token
<https://swagger.io/docs/specification/authentication/bearer-authentication/>`_
or in the form of a query string parameter as shown below.

* Bearer token (recommended)::

      curl -X POST http://localhost:8000/api/v1/authorize/ \
           -H "Authorization: Bearer <org-uuid> <token>" \
           -d "username=<username>&password=<password>"

* Querystring::

      curl -X POST http://localhost:8000/api/v1/authorize/?uuid=<org-uuid>&token=<token> \
           -d "username=<username>&password=<password>"

Requests which contain an invalid token will receive a ``403`` HTTP error.

For information on how to configure FreeRADIUS to send the bearer tokens, see
`Configure the REST module </developer/freeradius.html#configure-the-rest-module>`_.

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

    /api/v1/authorize/

Example:

.. code-block:: text

    POST /api/v1/authorize/ HTTP/1.1 username=testuser&password=testpassword

========    ===========================
Param       Description
========    ===========================
username    Username for the given user
password    Password for the given user
========    ===========================

See also `OPENWISP_RADIUS_API_AUTHORIZE_REJECT
<settings.html#openwisp-radius-api-authorize-reject>`_.

Post Auth
---------

API endpoint designed to be used by FreeRADIUS ``postauth``.

Responds only to **POST**.

.. code-block:: text

    /api/v1/postauth/

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

    /api/v1/accounting/

GET
~~~

Returns a list of accounting objects

.. code-block:: text

    GET /api/v1/accounting/

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
      link: <http://testserver/api/v1/accounting/?page=2&page_size=1>; rel=\"next\",
            <http://testserver/api/v1/accounting/?page=3&page_size=1>; rel=\"last\"
      ....
      ....
    }

Note: Default page size is 10, which can be overridden using the `page_size` parameter.

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

User API endpoints
##################

These API endpoints are designed to be used by users
(eg: creating an account, changing their password,
obtaining access tokens, validating their phone number, etc.).

.. note::
  The API endpoints described below do not require the
  `Organization API Token <#organization-api-token>`_
  described in the beginning of this document.

  Some of them require the sending of the user API access token
  sent in the form of a "Bearer Token".

User Registration
-----------------

Used by users to create new accounts, usually to access the internet.

.. code-block:: text

  /api/v1/<organization-slug>/account/

Responds only to **POST**.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
username           string
email              string
password1          string
password2          string
phone_number       string (*)
===============    ===============================

(*) ``phone_number`` is required only when the organization has enabled
SMS verification in its "Organization RADIUS Settings".

Reset password
--------------

This is the classic "password forgotten recovery feature" which
sends a reset password token to the email of the user.

.. code-block:: text

    /api/v1/<organization-slug>/account/password/reset/

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

    /api/v1/<organization-slug>/account/password/reset/confirm/

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

    /api/v1/<organization-slug>/account/password/change/

Example:

.. code-block:: text

    curl -X POST http://localhost:8000/api/v1/<organization-slug>/account/password/change/ \
         -H "Authorization: Bearer <user-auth-token>"

Responds only to **POST**.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
new_password1      string
new_password2      string
===============    ===============================

Login (Obtain User Auth Token)
------------------------------

.. code-block:: text

    /api/v1/account/token/

Responds only to **POST**.

Returns:

- the user radius token, which can be used to authenticate
  the user in the captive portal by sending it in place of the user password
  (it will be passed to freeradius which in turn will send it to the
  `authorize API endpoint <#authorize>`_ which will recognize the token as
  the user passsword)
- the user API access token, which will be needed to authenticate the user to
  eventual subsequent API requests (eg: change password)

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

Return also the radius user token in the response.

.. code-block:: text

    /api/v1/account/token/validate/

Responds only to **POST**.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
token              string
===============    ===============================

User Radius Sessions
--------------------

**Requires the user auth token (Bearer Token)**.

Returns the radius sessions of the logged-in user and the organization specified
in the URL.

.. code-block:: text

    /api/v1/<organization-slug>/account/session/

Responds only to **GET**.

Create SMS token
----------------

**Requires the user auth token (Bearer Token)**.

Used for SMS verification, sends a code via SMS to the phone number of the user.

.. code-block:: text

    /api/v1/<organization-slug>/account/phone/token/

Responds only to **POST**.

No parameters required.

Verify/Validate SMS token
-------------------------

**Requires the user auth token (Bearer Token)**.

Used for SMS verification, allows users to validate the code they receive via SMS.

.. code-block:: text

    /api/v1/<organization-slug>/account/phone/verify/

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

.. code-block:: text

    /api/v1/<organization-slug>/account/phone/change/

Responds only to **POST**.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
phone_number       string
===============    ===============================

Batch user creation
-------------------

.. code-block:: text

    /api/v1/batch/

.. note::
  This API endpoint allows to use the features described in :doc:`/user/importing_users`
  and :doc:`/user/generating_users`.

Responds only to **POST**, used to save a ``RadiusBatch`` instance.

In the response, you can find the field ``user_credentials`` containing the list of users created
(example: [['username', 'password'], ['sample_user', 'BBuOb5sN']]") and field ``pdf_link``
containing a download link to a PDF file containing user credentials.

It is possible to generate the users of the ``RadiusBatch`` with two different strategies: csv or prefix.

The csv method needs the following parameters:

===============    ===============================
Param              Description
===============    ===============================
name               Name of the operation
strategy           csv
csvfile            file with the users
expiration_date    date of expiration of the users
===============    ===============================

These others are for the prefix method:

===============    ==================================
Param              Description
===============    ==================================
name               name of the operation
strategy           prefix
prefix             prefix for the generation of users
number_of_users    number of users
expiration_date    date of expiration of the users
===============    ==================================
