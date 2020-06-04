=================
API Documentation
=================

openwisp-radius provides an API that can be used by freeradius to perform
the following operations:

- Authorize
- Accounting
- Post Auth

The API also provides other features that can be useful to perform integrations
with third-party software:

- Batch User Creation
- Login (Obtain User Auth Token)

API Token
---------

Only requests containing the right API token and Organization UUID will able
to talk to the API endpoints.

You can get (and set) the value of the api token in the organization
configuration page on the OpenWISP dashboard
(select your organization in ``/admin/openwisp_users/organization/``):

.. image:: ../images/token.png
   :alt: Organization Radius Token

It is highly recommended that you use a hard to guess value, longer than 15 characters
containing both letters and numbers. Eg: "165f9a790787fc38e5cc12c1640db2300648d9a2"

You will also need the UUID of your organization from the organization change page
(select your organization in ``/admin/openwisp_users/organization/``):

.. image:: ../images/org-uuid.png
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
`Configure the REST module <freeradius.html#configure-the-rest-module>`_.

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

Authorize
---------

.. code-block:: text

    /api/v1/authorize/

Responds to only **POST**, used for authorizing a given username and password.

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

PostAuth
--------

.. code-block:: text

    /api/v1/postauth/

Sets the response data to None in order to instruct
FreeRADIUS to avoid processing the response body.

Responds only to **POST**.

Batch user creation
-------------------

.. code-block:: text

    /api/v1/batch/

.. note::
  This API endpoint allows to use the features described in :doc:`importing_users`
  and :doc:`generating_users`.

Responds only to **POST**, used to save a ``RadiusBatch`` instance.
It returns the information of the batch operation and the list of the users generated.
It is possible to generate the users of the ``RadiusBatch`` with two different strategies: csv or prefix.

The csv method needs the following parameters:

===============    ===============================
Param              Description
===============    ===============================
name               Name of the operation
strategy           "csv"
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

Login (Obtain User Auth Token)
------------------------------

.. code-block:: text

    /api/v1/account/token/

.. note::
  This endpoint does not require the sending of the `API Token <#api-token>`_
  described in the beginning of this document.

Responds only to **POST**.

Returns the user access token, which can be used to authenticate
the user via the freeradius authorization mechanism.

Parameters:

===============    ===============================
Param              Description
===============    ===============================
username           string
password           string
===============    ===============================
