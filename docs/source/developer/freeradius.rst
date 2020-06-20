==============================================
Installation and configuration of Freeradius 3
==============================================

This guide explains how to install and configure `freeradius 3 <https://freeradius.org>`_
in order to make it work with `openwisp-radius <https://github.com/openwisp/openwisp-radius/>`_.

.. note::
    The guide is written for debian based systems, other linux distributions can work as well but the
    name of packages and files may be different.

How to install freeradius 3
---------------------------

First of all, become root:

.. code-block:: shell

    sudo -s

Let's add the PPA repository for the Freeradius 3.x stable branch:

.. note::
    If you use a recent version of Debian like **Stretch** (9) or Ubuntu **Bionic** (18),
    you should skip the following command and use the official repositories.

.. code-block:: shell

    apt-add-repository ppa:freeradius/stable-3.0

Update the list of available packages:

.. code-block:: shell

    apt update

These packages are always needed:

.. code-block:: shell

    apt install freeradius freeradius-rest

If you use MySQL:

.. code-block:: shell

    apt install freeradius-mysql

If you use PostgreSQL:

.. code-block:: shell

    apt install freeradius-postgresql

Configuring Freeradius 3
------------------------

For a complete reference on how to configure freeradius please read the
`Freeradius wiki, configuration files <https://wiki.freeradius.org/config/Configuration-files>`_
and their `configuration tutorial <https://wiki.freeradius.org/guide/HOWTO>`_.

.. note::
    The path to freeradius configuration could be different on your system.
    This article use the ``/etc/freeradius/`` directory that ships with recent
    debian distributions and its derivatives

Refer to the `mods-available documentation <https://networkradius.com/doc/3.0.10/raddb/mods-available/home.html>`_
for the available configuration values.

Enable the configured modules
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

First of all enable the ``sql``, ``rest`` and ``sqlcounter`` modules:

.. code-block:: shell

    ln -s /etc/freeradius/mods-available/sql /etc/freeradius/mods-enabled/sql
    ln -s /etc/freeradius/mods-available/rest /etc/freeradius/mods-enabled/rest
    ln -s /etc/freeradius/mods-available/sqlcounter /etc/freeradius/mods-enabled/sqlcounter

Configure the SQL module
^^^^^^^^^^^^^^^^^^^^^^^^

Once you have configured properly an SQL server, e.g. PostgreSQL:, and you can
connect with a username and password edit the file ``/etc/freeradius/mods-available/sql``
to configure Freeradius to use the relational database.

Change the configuration for ``driver``, ``dialect``, ``server``, ``port``, ``login``, ``password``, ``radius_db`` as you need to fit your SQL server configuration.

Refer to the `sql module documentation <https://networkradius.com/doc/3.0.10/raddb/mods-available/sql.html>`_ for the available configuration values.

Example configuration using the PostgreSQL database:

.. code-block:: ini

    # /etc/freeradius/mods-available/sql

    driver = "rlm_sql_postgresql"
    dialect = "postgresql"

    # Connection info:
    server = "localhost"
    port = 5432
    login = "<user>"
    password = "<password>"
    radius_db = "radius"

.. _configure-sqlcounters:

Configure the SQL counters
^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``sqlcounter`` module is used to `enforce session limits </user/enforcing_limits.html>`_.

The ``mods-available/sqlcounter`` should look like the following:

.. code-block:: ini

    # /etc/freeradius/mods-available/sqlcounter

    # The dailycounter is included by default in the freeradius conf
    sqlcounter dailycounter {
        sql_module_instance = sql
        dialect = ${modules.sql.dialect}

        counter_name = Daily-Session-Time
        check_name = Max-Daily-Session
        reply_name = Session-Timeout

        key = User-Name
        reset = daily

        $INCLUDE ${modconfdir}/sql/counter/${dialect}/${.:instance}.conf
    }

    # The noresetcounter is included by default in the freeradius conf
    sqlcounter noresetcounter {
        sql_module_instance = sql
        dialect = ${modules.sql.dialect}

        counter_name = Max-All-Session-Time
        check_name = Max-All-Session
        key = User-Name
        reset = never

        $INCLUDE ${modconfdir}/sql/counter/${dialect}/${.:instance}.conf
    }

    # The dailybandwidthcounter is added for openwisp-radius
    sqlcounter dailybandwidthcounter {
       counter_name = Max-Daily-Session-Traffic
       check_name = Max-Daily-Session-Traffic
       sql_module_instance = sql
       key = 'User-Name'
       reset = daily
       query = "SELECT SUM(acctinputoctets + acctoutputoctets) \
                FROM radacct \
                WHERE UserName='%{${key}}' \
                AND UNIX_TIMESTAMP(acctstarttime) + acctsessiontime > '%%b'"
    }

.. note::
  If your freeradius installation fails to start with an error similar to:

  ``/etc/raddb/sites-enabled/default[440]: Failed to find "dailycounter" as a module or policy.``

  We need enable the ``sqlcounter`` in a special way. The ``modules`` section
  of ``radiusd.conf`` should look as shown below.  This is because of a `bug in freeradius
  <http://lists.freeradius.org/pipermail/freeradius-users/2015-February/075870.html>`_.
  This should be solved in a future release of freeradius.

.. code-block:: ini

    # /etc/freeradius/radiusd.conf
    modules {
        # ..
        $INCLUDE mods-enabled
        $INCLUDE mods-available/sqlcounter
        # ..
    }

.. _configure-rest-module:

Configure the REST module
^^^^^^^^^^^^^^^^^^^^^^^^^

Configure the rest module by editing the file ``/etc/freeradius/mods-enabled/rest``,
substituting ``<url>`` with your django project's URL, (for example, if you are
testing a development environment, the URL could be ``http://127.0.0.1:8000``,
otherwise in production could be something like ``https://openwisp2.mydomain.org``)-

Refer to the `rest module documentation <https://networkradius.com/doc/3.0.10/raddb/mods-available/rest.html>`_
for the available configuration values.

.. code-block:: ini

    # /etc/freeradius/mods-enabled/rest

    connect_uri = "<url>"

    authorize {
        uri = "${..connect_uri}/api/v1/authorize/"
        method = 'post'
        body = 'json'
        data = '{"username": "%{User-Name}", "password": "%{User-Password}"}'
        tls = ${..tls}
    }

    # this section can be left empty
    authenticate {}

    post-auth {
        uri = "${..connect_uri}/api/v1/postauth/"
        method = 'post'
        body = 'json'
        data = '{"username": "%{User-Name}", "password": "%{User-Password}", "reply": "%{reply:Packet-Type}", "called_station_id": "%{Called-Station-ID}", "calling_station_id": "%{Calling-Station-ID}"}'
        tls = ${..tls}
    }

    accounting {
        uri = "${..connect_uri}/api/v1/accounting/"
        method = 'post'
        body = 'json'
        data = '{"status_type": "%{Acct-Status-Type}", "session_id": "%{Acct-Session-Id}", "unique_id": "%{Acct-Unique-Session-Id}", "username": "%{User-Name}", "realm": "%{Realm}", "nas_ip_address": "%{NAS-IP-Address}", "nas_port_id": "%{NAS-Port}", "nas_port_type": "%{NAS-Port-Type}", "session_time": "%{Acct-Session-Time}", "authentication": "%{Acct-Authentic}", "input_octets": "%{Acct-Input-Octets}", "output_octets": "%{Acct-Output-Octets}", "called_station_id": "%{Called-Station-Id}", "calling_station_id": "%{Calling-Station-Id}", "terminate_cause": "%{Acct-Terminate-Cause}", "service_type": "%{Service-Type}", "framed_protocol": "%{Framed-Protocol}", "framed_ip_address": "%{Framed-IP-Address}"}'
        tls = ${..tls}
    }

Configure the site
^^^^^^^^^^^^^^^^^^

Configure the ``authorize``, ``authenticate`` and ``postauth`` section
as follows, substituting the occurrences of ``<api_token>`` & ``<org-uuid>`` with
the value of `your organization's UUID & api_token values </user/api.html#organization-api-token>`_:

.. code-block:: ini

    # /etc/freeradius/sites-enabled/default

    server default {

        api_token_header = "Authorization: Bearer <org-uuid> <api_token>"

        authorize {
            update control { &REST-HTTP-Header += "${...api_token_header}" }
            rest
            sql
            dailycounter
            noresetcounter
            dailybandwidthcounter
        }

        # this section can be left empty
        authenticate {}

        post-auth {
            update control { &REST-HTTP-Header += "${...api_token_header}" }
            rest

            Post-Auth-Type REJECT {
                update control { &REST-HTTP-Header += "${....api_token_header}" }
                rest
            }
        }

        accounting {
            update control { &REST-HTTP-Header += "${...api_token_header}" }
            rest
        }
    }

Please also ensure that ``acct_unique`` is present in tge ``pre-accounting`` section:

.. code-block:: ini

    preacct {
        # ...
        acct_unique
        # ...
    }

Restart freeradius to make the configuration effective
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Restart freeradius to load the new configuration:

.. code-block:: shell

    service freeradius restart
    # alternatively if you are using systemd
    systemctl restart freeradius

In case of errors you can run `freeradius in debug mode
<https://wiki.freeradius.org/guide/radiusd-X>`_ by running
``freeradius -X`` in order to find out the reason of the failure.

**A common problem, especially during development and testing, is that the
openwisp-radius application may not be running**, in that case you can find
out how to run the django development server in the
`Install for development </developer/setup.html#installing-for-development>`_ section.

Also make sure that this server runs on the port specified in
``/etc/freeradius/mods-enabled/rest``.

You may also want to take a look at the `Freeradius documentation
<https://freeradius.org/documentation/>`_ for further information that is freeradius specific.

Reconfigure the development environment using PostgreSQL
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You'll have to reconfigure the development environment as well before being able
to use openwisp-radius for managing the freeradius databases.

If you have installed for development, create a file ``tests/local_settings.py``
and add the following code to configure the database:

.. code-block:: python

   # openwisp-radius/tests/local_settings.py
     DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql_psycopg2',
            'NAME': '<db_name>',
            'USER': '<db_user>',
            'PASSWORD': '<db_password>',
            'HOST': '127.0.0.1',
            'PORT': '5432'
        },
     }

Make sure the database by the name ``<db_name>`` is created and also the
role ``<db_user>`` with ``<db_password>`` as password.

Radius Checks: ``is_active`` & ``valid_until``
----------------------------------------------

openwisp-radius provides the possibility to extend the freeradius
query in order to introduce ``is_active`` and ``valid_until`` checks.

An example using MySQL is:

.. code-block:: ini

    # /etc/freeradius/mods-config/sql/main/mysql/queries.conf
    authorize_check_query = "SELECT id, username, attribute, value, op \
                             FROM ${authcheck_table} \
                             WHERE username = '%{SQL-User-Name}' \
                             AND is_active = TRUE \
                             AND valid_until >= CURDATE() \
                             ORDER BY id"

Using Radius Checks for Authorization Information
-------------------------------------------------

Traditionally, when using an SQL backend with Freeradius, user authorization information such as User-Name and
`"known good" <https://freeradius.org/radiusd/man/rlm_pap.html>`_ password are stored using the *radcheck*
table provided by Freeradius' default SQL schema.  openwisp-radius utilizes Freeradius'
`rlm_rest <https://networkradius.com/doc/current/raddb/mods-available/rest.html>`_ module in order to
take advantage of the built in user management and authentication capabilities of Django.
(See :ref:`configure-rest-module` and `User authentication in Django <https://docs.djangoproject.com/en/dev/topics/auth/>`_)

For existing Freeradius deployments or in cases where it is preferred to utilize Freeradius' *radcheck* table for
storing user credentials it is possible to utilize `rlm_sql <https://wiki.freeradius.org/modules/Rlm_sql>`_
in parallel with (or instead of) `rlm_rest <https://networkradius.com/doc/current/raddb/mods-available/rest.html>`_
for authorization.

.. note::
    Bypassing the openwisp-radius' REST API for authorization means you will have to manually create
    Radius Check 'password' entries for each user you want to authenticate with Freeradius.

Password hashing
^^^^^^^^^^^^^^^^

By default Django will use `PBKDF2 <https://en.wikipedia.org/wiki/PBKDF2>`_ to store all passwords in the database.
(See `Password management in Django <https://docs.djangoproject.com/en/dev/topics/auth/passwords/)>`_).
The default password hashing and storage algorithms in Django are not compatible with those used by Freeradius.
Therefore, a default set of Freeradius compatible password storage methods have been provided for deployments that make use
of Radius Checks for user credentials.

* Cleartext-Password
* NT-Password
* LM-Password
* MD5-Password
* SMD5-Password
* SHA-Password
* SSHA-Password
* Crypt-Password

.. note::
    Only the Crypt-Password hashing attribute is recommended for new entries as it makes
    use of the sha512_crypt feature supported by most Unix/Linux operating systems.
    (See `passlib.hash <https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html#active-unix-hashes>`_)
    The other password hashing algorithms have been provided for backward compatibility.

Configuration
^^^^^^^^^^^^^

To configure support for accessing user credentials with Radius Checks ensure
the ``authorize`` section of your site as follows contains the ``sql`` module:

.. code-block:: ini

    # /etc/freeradius/sites-available/default

    authorize {
        # ...
        sql  # <-- the sql module
        # ...
    }

Now you can add new Radius Check entries with one of the
supported hashing/storage methods mentioned above.

Additional Password Formats
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Freeradius supports additional password hashing algorithms which are listed in the Freeradius
`rlm_pap <https://freeradius.org/radiusd/man/rlm_pap.html>`_ documentation.  If your existing
deployment makes use of one of these or you would like to request an addition to openwisp-radius
please see the documentation section on :doc:`/developer/contributing`.

Keep in mind that using Radius Checks for accessing user credentials is considered an edge case in openwisp-radius.
Full compatibility with new and existing features is not guaranteed.

Debugging
---------

In this section we will explain how to debug your freeradius instance.

Start freeradius in debug mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When debugging we suggest you to open up a dedicated terminal window to run freeradius in debug mode:

.. code-block:: shell

    # we need to stop the main freeradius process first
    service freeradius stop
    # alternatively if you are using systemd
    systemctl stop freeradius
    # launch freeradius in debug mode
    freeradius -X

Testing authentication and authorization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can do this with ``radtest``:

.. code-block:: shell

    # radtest <username> <password> <host> 10 <secret>
    radtest admin admin localhost 10 testing123

A successful authentication will return similar output::

    Sent Access-Request Id 215 from 0.0.0.0:34869 to 127.0.0.1:1812 length 75
    	User-Name = "admin"
    	User-Password = "admin"
    	NAS-IP-Address = 127.0.0.1
    	NAS-Port = 10
    	Message-Authenticator = 0x00
    	Cleartext-Password = "admin"
    Received Access-Accept Id 215 from 127.0.0.1:1812 to 0.0.0.0:0 length 20

While an unsuccessful one will look like the following::

    Sent Access-Request Id 85 from 0.0.0.0:51665 to 127.0.0.1:1812 length 73
    	User-Name = "foo"
    	User-Password = "bar"
    	NAS-IP-Address = 127.0.0.1
    	NAS-Port = 10
    	Message-Authenticator = 0x00
    	Cleartext-Password = "bar"
    Received Access-Reject Id 85 from 127.0.0.1:1812 to 0.0.0.0:0 length 20
    (0) -: Expected Access-Accept got Access-Reject

Alternatively, you can use ``radclient`` which allows more complex tests; in the following
example we show how to test an authentication request which includes ``Called-Station-ID``
and ``Calling-Station-ID``:

.. code-block:: shell

    user="foo"
    pass="bar"
    called="00-11-22-33-44-55:localhost"
    calling="00:11:22:33:44:55"
    request="User-Name=$user,User-Password=$pass,Called-Station-ID=$called,Calling-Station-ID=$calling"
    echo $request | radclient localhost auth testing123

Testing accounting
^^^^^^^^^^^^^^^^^^

You can do this with ``radclient``, but first of all you will have to create a text file
like the following one::

    # /tmp/accounting.txt

    Acct-Session-Id = "35000006"
    User-Name = "jim"
    NAS-IP-Address = 172.16.64.91
    NAS-Port = 1
    NAS-Port-Type = Async
    Acct-Status-Type = Interim-Update
    Acct-Authentic = RADIUS
    Service-Type = Login-User
    Login-Service = Telnet
    Login-IP-Host = 172.16.64.25
    Acct-Delay-Time = 0
    Acct-Session-Time = 261
    Acct-Input-Octets = 9900909
    Acct-Output-Octets = 10101010101
    Called-Station-Id = 00-27-22-F3-FA-F1:hostname
    Calling-Station-Id = 5c:7d:c1:72:a7:3b

Then you can call ``radclient``:

.. code-block:: shell

    radclient -f /tmp/accounting.txt -x 127.0.0.1 acct testing123

You should get the following output::

    Sent Accounting-Request Id 83 from 0.0.0.0:51698 to 127.0.0.1:1813 length 154
    	Acct-Session-Id = "35000006"
    	User-Name = "jim"
    	NAS-IP-Address = 172.16.64.91
    	NAS-Port = 1
    	NAS-Port-Type = Async
    	Acct-Status-Type = Interim-Update
    	Acct-Authentic = RADIUS
    	Service-Type = Login-User
    	Login-Service = Telnet
    	Login-IP-Host = 172.16.64.25
    	Acct-Delay-Time = 0
    	Acct-Session-Time = 261
    	Acct-Input-Octets = 9900909
    	Acct-Output-Octets = 1511075509
    	Called-Station-Id = "00-27-22-F3-FA-F1:hostname"
    	Calling-Station-Id = "5c:7d:c1:72:a7:3b"
    Received Accounting-Response Id 83 from 127.0.0.1:1813 to 0.0.0.0:0 length 20

Customizing your configuration
------------------------------

You can further customize your freeradius configuration and exploit the many features of freeradius but
you will need to test how your configuration plays with *openwisp-radius*.
