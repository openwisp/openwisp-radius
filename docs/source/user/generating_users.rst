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
                                 --organization=<organization-name> \
                                 --prefix <prefix> \
                                 --n <number_of_users> \
                                 --expiration <expiration_date> \
                                 --password-length <password_length> \
                                 --output <path_to_pdf_file>

.. note::
   The expiration, password-length and output are optional parameters. The options expiration and password-length default to never and 8 respectively. If output parameter is not provided, pdf file is not created on the server and can be accessed from the admin interface.

Adding from admin inteface
--------------------------

At the url ``/admin/openwisp_radius/radiusbatch/add`` one can directly generate users using the prefix and the number of users.

A PDF containing the list of user credentials can be downloaded from the admin interface:

.. image:: /images/download_user_credentials_button.png
   :alt: Downlaod user credentials button in admin interface

The contents of the PDF is in format of a table of users & their passwords:

.. image:: /images/pdf_of_user_list.png
   :alt: Sample contents of the user credentials PDF file

Usage Demonstration:

.. image:: /images/add_users_prefix.gif
   :alt: Demo: adding users from prefix
