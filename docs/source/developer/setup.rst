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

    # REQUIRED: update base python packages
    pip install -U pip setuptools wheel
    # install openwisp-radius
    pip install openwisp-radius

Install development version
---------------------------

Install tarball:

.. code-block:: shell

    # REQUIRED: update base python packages
    pip install -U pip setuptools wheel
    # install openwisp-radius
    pip install https://github.com/openwisp/openwisp-radius/tarball/master

Alternatively you can install via pip using git:

.. code-block:: shell

    # REQUIRED: update base python packages
    pip install -U pip setuptools wheel
    # install openwisp-radius
    pip install -e git+git://github.com/openwisp/openwisp-radius#egg=openwisp-radius

If you want to contribute, install your cloned fork:

.. code-block:: shell

    # REQUIRED: update base python packages
    pip install -U pip setuptools wheel
    # install your forked openwisp-radius
    git clone git@github.com:<your_fork>/openwisp-radius.git
    cd openwisp-radius
    pip install -e .

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
        'dj_rest_auth',
        'dj_rest_auth.registration',
        # openwisp radius
        'openwisp_radius',
        'openwisp_users',
        'private_storage',
        'drf_yasg',
    ]

These modules are optional, add them only if you need the
`social login <../user/social_login.html>`_ feature:

.. code-block:: python

    INSTALLED_APPS += [
        # social login
        'allauth.socialaccount',
        'allauth.socialaccount.providers.facebook',
        'allauth.socialaccount.providers.google',
    ]

Add media locations in ``settings.py``:

.. code-block:: python

    MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
    PRIVATE_STORAGE_ROOT = os.path.join(MEDIA_ROOT, 'private')

Also, add ``AUTH_USER_MODEL``, ``AUTHENTICATION_BACKENDS`` and ``SITE_ID`` to
your ``settings.py``:

.. code-block:: python

    AUTH_USER_MODEL = 'openwisp_users.User'
    SITE_ID = 1
    AUTHENTICATION_BACKENDS = (
        'openwisp_users.backends.UsersAuthenticationBackend',
    )

Add allowed freeradius hosts  in ``settings.py``:

.. code-block:: python

    OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS = ['127.0.0.1']

.. note::
    Read more about `freeradius allowed hosts in settings page
    <../user/settings.html#openwisp-radius-freeradius-allowed-hosts>`_.

Add the URLs to your main ``urls.py``:

.. code-block:: python

    from openwisp_radius.urls import get_urls

    urlpatterns = [
        # ... other urls in your project ...

        # django admin interface urls
        path('admin/', admin.site.urls),
        # openwisp-radius urls
        path('api/v1/', include('openwisp_utils.api.urls')),
        path('api/v1/', include('openwisp_users.api.urls')),
        path('accounts/', include('openwisp_users.accounts.urls')),
        path('', include('openwisp_radius.urls', namespace='radius'))
    ]

Then run:

.. code-block:: shell

    ./manage.py migrate

Migrating an existing freeradius database
-----------------------------------------

If you already have a freeradius 3 database with the default schema, you should
be able to use it with openwisp-radius (and extended apps) easily:

1. first of all, back up your existing database;
2. configure django to connect to your existing database;
3. fake the first migration (which only replicates the default freeradius schema)
   and then launch the rest of migrations normally, see the examples below to
   see how to do this.

.. code-block:: shell

    ./manage.py migrate --fake openwisp-radius 0001_initial_freeradius
    ./manage.py migrate

Automated periodic tasks
------------------------

Some periodic commands are required in production environments to enable certain
features and facilitate database cleanup.
There are two ways to automate these tasks:

1. Celery-beat (Recommended Method)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. You need to create a `celery configuration file as it's created in example file <https://github.com/openwisp/openwisp-radius/tree/master/tests/openwisp2/celery.py>`_.

2. Add celery to ``__init__.py`` of your project:

.. code-block:: python

    from .celery import app as celery_app

    __all__ = ['celery_app']

3. In the settings.py, `configure the CELERY_BEAT_SCHEDULE <https://github.com/openwisp/openwisp-radius/tree/master/tests/openwisp2/settings.py#L141>`_. Some celery tasks take an argument, for instance
``365`` is given here for ``delete_old_radacct`` in the example settings.
These arguments are passed to their respective management commands. More information about these parameters can be
found at the `management commands page <../user/management_commands.html>`_.

.. note::
    Celery tasks do not start with django server and need to be
    started seperately, please read about running `celery and
    celery-beat <./setup.html#celery-usage>`_ tasks.

2. Crontab (Legacy Method)
^^^^^^^^^^^^^^^^^^^^^^^^^^

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

.. note::
    More information can be found at the
    `management commands page <../user/management_commands.html>`_.

Installing for development
--------------------------

Install python3-dev and gcc:

.. code-block:: shell

    sudo apt install python3-dev gcc

Install sqlite:

.. code-block:: shell

    sudo apt install sqlite3 libsqlite3-dev libpq-dev

Install mysqlclient:

.. code-block:: shell

    sudo apt install libmysqlclient-dev libssl-dev

.. note::
    If you are on Debian 10 or 9 you may need to install ``default-libmysqlclient-dev`` instead

Install xmlsec1:

.. code-block:: shell

    sudo apt install xmlsec1

Install your forked repo:

.. code-block:: shell

    git clone git://github.com/<your_username>/openwisp-radius
    cd openwisp-radius/
    pip install -e .[saml,openvpn_status]

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

Celery Usage
------------

To run celery, you need to start redis-server. You can `install redis on your machine
<https://redis.io/download>`_ or `install docker <https://docs.docker.com/get-docker/>`_
and run redis inside docker container:

.. code-block:: shell

    docker run -p 6379:6379 --name openwisp-redis -d redis:alpine

Run celery (it is recommended to use a tool like supervisord in production):

.. code-block:: shell

    # Optionally, use ``--detach`` argument to avoid using multiple terminals
    celery -A openwisp2 worker -l info
    celery -A openwisp2 beat -l info

Troubleshooting
---------------

If you encounter any issue during installation, run:

.. code-block:: shell

    pip install -e .[saml] -r requirements-test.txt

instead of ``pip install -r requirements-test.txt``
