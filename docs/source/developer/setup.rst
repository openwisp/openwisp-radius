=====
Setup
=====

Create a virtual environment
----------------------------

Please use a `python virtual environment <https://docs.python.org/3/library/venv.html>`_.
It keeps everybody on the same page, helps reproducing bugs and resolving problems.

We highly suggest to use **virtualenvwrapper**, please refer to the official `virtualenvwrapper installation page <https://virtualenvwrapper.readthedocs.io/en/latest/install.html>`_ and come back here when ready to proceed.

.. code-block:: shell

    # create virtualenv
    mkvirtualenv radius

.. note::
    If you encounter an error like ``Python could not import the module virtualenvwrapper``,
    add ``VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3`` and run ``source virtualenvwrapper.sh`` again :)

Install required system packages
--------------------------------

Install packages required by Weasyprint for your OS:

 - `Linux <https://weasyprint.readthedocs.io/en/stable/install.html#linux>`_
 - `MacOS <https://weasyprint.readthedocs.io/en/stable/install.html#macos>`_
 - `Windows <https://weasyprint.readthedocs.io/en/stable/install.html#windows>`_

Install stable version from pypi
--------------------------------

Install from pypi:

.. code-block:: shell

    pip install openwisp-radius

Install development version
---------------------------

Install tarball:

.. code-block:: shell

    pip install https://github.com/openwisp/openwisp-radius/tarball/master

Alternatively you can install via pip using git:

.. code-block:: shell

    pip install -e git+git://github.com/openwisp/openwisp-radius#egg=openwisp-radius

If you want to contribute, install your cloned fork:

.. code-block:: shell

    git clone git@github.com:<your_fork>/openwisp-radius.git
    cd openwisp-radius
    python setup.py develop

Setup (integrate in an existing django project)
-----------------------------------------------

The ``settings.py`` file of your project should have at least the following
modules listed ``INSTALLED_APPS``:

.. code-block:: python

    INSTALLED_APPS = [
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        # openwisp admin theme
        'openwisp_utils.admin_theme',
        # all-auth
        'django.contrib.sites',
        'allauth',
        'allauth.account',
        # admin
        'django.contrib.admin',
        # rest framework
        'rest_framework',
        'django_filters',
        # registration
        'rest_framework.authtoken',
        'rest_auth',
        'rest_auth.registration',
        # openwisp radius
        'openwisp_radius',
        'openwisp_users',
    ]

These modules are optional, add them only if you need the
`social login </user/social_login.html>`_. feature:

.. code-block:: python

    INSTALLED_APPS += [
        # social login
        'allauth.socialaccount',
        'allauth.socialaccount.providers.facebook',
        'allauth.socialaccount.providers.google',
    ]

Add the URLs to your main ``urls.py``:

.. code-block:: python

    urlpatterns = [
        # ... other urls in your project ...

        # openwisp-radius urls
        # keep the namespace argument unchanged
        url(r'^', include('openwisp_radius.urls', namespace='radius')),
    ]

Then run:

.. code-block:: shell

    ./manage.py migrate

Migrating an existing freeradius database
-----------------------------------------

If you already have a freeradius 3 database with the default schema, you should
be able to use it with openwisp-radius (and openwisp-radius) easily:

1. first of all, back up your existing database;
2. configure django to connect to your existing database;
3. fake the first migration (which only replicates the default freeradius schema)
   and then launch the rest of migrations normally, see the examples below to
   see how to do this.

.. code-block:: shell

    ./manage.py migrate --fake openwisp-radius 0001_initial_freeradius
    ./manage.py migrate


Installing for development
--------------------------

Install python3-dev and gcc:

.. code-block:: shell

    sudo apt-get install python3-dev gcc

Install sqlite:

.. code-block:: shell

    sudo apt-get install sqlite3 libsqlite3-dev libpq-dev

Install mysqlclient:

.. code-block:: shell

    sudo apt-get install libmysqlclient-dev libssl-dev

.. note::
    If you are on Debian 10 or 9 you may need to install ``default-libmysqlclient-dev`` instead

Install your forked repo:

.. code-block:: shell

    git clone git://github.com/<your_username>/openwisp-radius
    cd openwisp-radius/
    python setup.py develop

Install test requirements:

.. code-block:: shell

    pip install -r requirements-test.txt

Create database:

.. code-block:: shell

    cd tests/
    ./manage.py migrate
    ./manage.py createsuperuser

Launch development server:

.. code-block:: shell

    ./manage.py runserver

You can access the admin interface at http://127.0.0.1:8000/admin/.

Run tests with:

.. code-block:: shell

    ./runtests.py

Troubleshooting
---------------

If you encounter any issue during installation, run:

.. code-block:: shell

    pip install -r requirements.txt -r requirements-test.txt

instead of ``pip install -r requirements-test.txt``


Automating management commands
------------------------------

Some management commands are necessary to enable certain
features and also facilitate database cleanup. In a
production environment, it is highly recommended to
automate the usage of these commands by using cron jobs.

Edit the crontab with:

.. code-block:: shell

    crontab -e

Add and modify the following lines accordingly:

.. code-block:: shell

    # This command deletes RADIUS accounting sessions older than 365 days
    30 04 * * * <virtualenv_path>/bin/python <full/path/to>/manage.py delete_old_radacct 365

    # This command deletes RADIUS post-auth logs older than 365 days
    30 04 * * * <virtualenv_path>/bin/python <full/path/to>/manage.py delete_old_postauth 365

    # This command closes stale RADIUS sessions that have remained open for 15 days
    30 04 * * * <virtualenv_path>/bin/python <full/path/to>/manage.py cleanup_stale_radacct 15

    # This command deactivates expired user accounts which were created temporarily
    # (eg: for en event) and have an expiration date set.
    30 04 * * * <virtualenv_path>/bin/python <full/path/to>/manage.py deactivate_expired_users

    # This command deletes users that have expired (and should have
    # been deactivated by deactivate_expired_users) for more than
    # 18 months (which is the default duration)
    30 04 * * * <virtualenv_path>/bin/python <full/path/to>/manage.py delete_old_users

Be sure to replace ``<virtualenv_path>`` with the absolute path to the Python
virtual environment.

Also, change ``<full/path/to>`` to the directory where ``manage.py`` is.

To get the absolute path to ``manage.py`` when openwisp-radius is
installed for development, navigate to the base directory of
the cloned fork. Then, run:

.. code-block:: shell

    cd tests/
    pwd

More information can be found at the
`management commands page </user/management_commands.html>`_.
