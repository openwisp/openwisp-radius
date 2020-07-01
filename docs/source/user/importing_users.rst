===============
Importing users
===============

This feature can be used for importing users from a csv file. There are many features included in it such as:

* Importing users in batches: all of the users of a particular csv file would
  be stored in batches and can be retrieved/ deleted easily using the batch functions.
* Set an expiration date: Expiration date can be set for a batch after which the users
  would not able to authenticate to the RADIUS Server.
* Autogenerate usernames and passwords: The usernames and passwords are
  automatically generated if they aren't provided in the csv file.
  Usernames are generated from the email address whereas passwords are
  generated randomly and their lengths can be customized.
* Passwords are accepted in both cleartext and hash formats from the CSV.
* Send mails to users whose passwords have been generated automatically.

This operation can be performed via the admin interface,
with a management command or via the REST API.

CSV Format
----------

The CSV shall be of the format::

    username,password,email,firstname,lastname

Imported users with hashed passwords
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The hashes are directly stored in the database if they are of the `django hash format <https://docs.djangoproject.com/en/2.0/topics/auth/passwords/>`_.

For example, a password myPassword123, hashed using salted SHA1 algorithm, will look like::

    pbkdf2_sha256$100000$cKdP39chT3pW$2EtVk4Hhm1V65GNfYAA5AHj0uyD60f2CmqumqiB/gRk=

So a full CSV line containing that password would be::

    username,pbkdf2_sha256$100000$cKdP39chT3pW$2EtVk4Hhm1V65GNfYAA5AHj0uyD60f2CmqumqiB/gRk=,email@email.com,firstname,lastname

Importing users with clear-text passwords
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Clear-text passwords must be flagged with the prefix ``cleartext$``.

For example, if we want to use the password ``qwerty``,
we must use: ``cleartext$qwerty``.

Auto-generation of usernames and passwords
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Email is the only mandatory field of the CSV file.

Other fields like username and password will be auto-generated if omitted.

Emails will be sent to users whose usernames or passwords have been
auto-generated and contents of these emails can be customized too.

Here are some defined settings for doing that:

    * `OPENWISP_RADIUS_BATCH_MAIL_SUBJECT <settings.html#openwisp-radius-batch-mail-subject>`_
    * `OPENWISP_RADIUS_BATCH_MAIL_MESSAGE <settings.html#openwisp-radius-batch-mail-message>`_
    * `OPENWISP_RADIUS_BATCH_MAIL_SENDER <settings.html#openwisp-radius-batch-mail-sender>`_

Using the admin interface
-------------------------

.. note::
   The CSV uploaded must follow the `CSV format described above <#csv-format>`_.

To generate users from the admin interface, go to
``Home > Batch user creation operations > Add``
(URL: ``/admin/openwisp_radius/radiusbatch/add``),
set ``Strategy`` to ``Import from CSV``,
choose the CSV file to upload and save.

.. image:: /images/add_users_csv.gif
   :alt: Demo: adding users from CSV

Management command: ``batch_add_users``
---------------------------------------

This command imports users from a csv file. Usage is as shown below.

.. code-block:: shell

    ./manage.py batch_add_users --name <name_of_batch> \
                                --organization=<organization-slug> \
                                --file <filepath> \
                                --expiration <expiration_date> \
                                --password-length <password_length>
.. note::
    The expiration and password-length are optional parameters which default to never and 8 respectively.

REST API: Batch user creation
-----------------------------

See `API documentation: Batch user creation <./api.html#batch-user-creation>`_.
