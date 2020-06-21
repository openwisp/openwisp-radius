Available settings
------------------

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

When this setting is enabled, every accounting instance saved from the API will have its ``groupname`` attribute automatically filled in.
The value filled in will be the ``groupname`` of the ``RadiusUserGroup`` of the highest priority among the RadiusUserGroups related to the user with the ``username`` as in the accounting instance.
In the event there is no user in the database corresponding to the ``username`` in the accounting instance, the failure will be logged with `info` level but the accounting will be saved as usual.

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


Sending emails to users
-----------------------

Emails can be sent to users whose usernames or passwords have been autogenerated. The content of these emails can be customized with the settings explained below.

``OPENWISP_RADIUS_BATCH_MAIL_SUBJECT``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``Credentials``

It is the subject of the mail to be sent to the users. Eg: ``Login Credentials``.

``OPENWISP_RADIUS_BATCH_MAIL_MESSAGE``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``username: {}, password: {}``

The message should be a string in the format ``Your username is {} and password is {}``.

The text could be anything but should have the format string operator ``{}`` for ``.format`` operations to work.

``OPENWISP_RADIUS_BATCH_MAIL_SENDER``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Default**: ``settings.DEFAULT_FROM_EMAIL``

It is the sender email which is also to be configured in the SMTP settings.
The default sender email is a common setting from the `Django core settings  <https://docs.djangoproject.com/en/2.1/ref/settings/#default-from-email>`_ under ``DEFAULT_FROM_EMAIL``.
Currently, ``DEFAULT_FROM_EMAIL`` is set to to ``webmaster@localhost``.
