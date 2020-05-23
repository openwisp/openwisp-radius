================
Generating users
================

Many a times, a network admin might need to generate temporary users for events etc. This feature can be used for generating users by specifying a prefix and the number of users to be generated. There are many features included in it such as:

* Generating users in batches: all of the users of a particular prefix would be stored in batches and can be retrieved/ deleted easily using the batch functions.
* Set an expiration date: Expiration date can be set for a batch after which the users would not able to authenticate to the RADIUS Server.
* PDF: Get the usernames and passwords generated outputted into a PDF.

This can be accomplished from both the admin interface and the management command.

``prefix_add_users``
--------------------

This command generates users whose usernames start with a particular prefix. Usage is as shown below.

.. code-block:: shell

    ./manage.py prefix_add_users --name <name_of_batch> \
                                 --prefix <prefix> \
                                 --n <number_of_users>
                                 --expiration <expiration_date> \
                                 --password-length <password_length>

Note that the expiration and password-length are optional parameters which default to never and 8 respectively.

Adding from admin inteface
--------------------------

At the url ``/admin/openwisp_radius/radiusbatch/add`` one can directly generate users using the prefix and the number of users. A PDF can be downloaded immediately after the users have been generated.

.. image:: ../images/add_users_prefix.gif
   :alt: Demo: adding users from prefix
