Developer Installation Instructions
===================================

.. include:: ../partials/developer-docs.rst

.. contents:: **Table of Contents**:
    :depth: 2
    :local:

Dependencies
------------

- Python >= 3.8

Installing for Development
--------------------------

Install the system dependencies:

.. code-block:: shell

    sudo apt update
    sudo apt install -y sqlite3 libsqlite3-dev libpq-dev
    sudo apt install -y xmlsec1
    sudo apt install -y chromium-browser

Fork and clone the forked repository:

.. code-block:: shell

    git clone git://github.com/<your_fork>/openwisp-radius

Navigate into the cloned repository:

.. code-block:: shell

    cd openwisp-radius/

Launch Redis:

.. code-block:: shell

    docker-compose up -d redis

Setup and activate a virtual-environment (we'll be using `virtualenv
<https://pypi.org/project/virtualenv/>`_):

.. code-block:: shell

    python -m virtualenv env
    source env/bin/activate

Make sure that your base python packages are up to date before moving to
the next step:

.. code-block:: shell

    pip install -U pip wheel setuptools

Install development dependencies:

.. code-block:: shell

    pip install -e .[saml,openvpn_status]
    pip install -r requirements-test.txt
    sudo npm install -g prettier

Install WebDriver for Chromium for your browser version from
https://chromedriver.chromium.org/home and Extract ``chromedriver`` to one
of directories from your ``$PATH`` (example: ``~/.local/bin/``).

Create database:

.. code-block:: shell

    cd tests/
    ./manage.py migrate
    ./manage.py createsuperuser

Launch celery worker (for background jobs):

.. code-block:: shell

    celery -A openwisp2 worker -l info

Launch development server:

.. code-block:: shell

    ./manage.py runserver

You can access the admin interface at ``http://127.0.0.1:8000/admin/``.

Run tests with:

.. code-block:: shell

    ./runtests.py --parallel

Run quality assurance tests with:

.. code-block:: shell

    ./run-qa-checks

Alternative Sources
-------------------

Pypi
~~~~

To install the latest Pypi:

.. code-block:: shell

    pip install openwisp-radius

Github
~~~~~~

To install the latest development version tarball via HTTPs:

.. code-block:: shell

    pip install https://github.com/openwisp/openwisp-radius/tarball/master

Alternatively you can use the git protocol:

.. code-block:: shell

    pip install -e git+git://github.com/openwisp/openwisp-radius#egg=openwisp_radius[saml,openvpn_status]

.. _radius_migrate_existing_freeradius_db:

Migrating an existing freeradius database
-----------------------------------------

If you already have a freeradius 3 database with the default schema, you
should be able to use it with openwisp-radius (and extended apps) easily:

1. first of all, back up your existing database;
2. configure django to connect to your existing database;
3. fake the first migration (which only replicates the default freeradius
   schema) and then launch the rest of migrations normally, see the
   examples below to see how to do this.

.. code-block:: shell

    ./manage.py migrate --fake openwisp-radius 0001_initial_freeradius
    ./manage.py migrate

Troubleshooting Steps for Common Installation Issues
----------------------------------------------------

If you encounter any issue during installation, run:

.. code-block:: shell

    pip install -e .[saml] -r requirements-test.txt

instead of ``pip install -r requirements-test.txt``
