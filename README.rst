openwisp-radius
===============

.. image:: https://github.com/openwisp/openwisp-radius/workflows/OpenWISP%20Radius%20CI%20Build/badge.svg?branch=master
    :target: https://github.com/openwisp/openwisp-radius/actions?query=workflow%3A%22OpenWISP+Radius+CI+Build%22
    :alt: CI build status

.. image:: https://coveralls.io/repos/github/openwisp/openwisp-radius/badge.svg?branch=master
    :target: https://coveralls.io/github/openwisp/openwisp-radius?branch=master
    :alt: Test Coverage

.. image:: https://img.shields.io/librariesio/release/github/openwisp/openwisp-radius
    :target: https://libraries.io/github/openwisp/openwisp-radius#repository_dependencies
    :alt: Dependency monitoring

.. image:: https://img.shields.io/gitter/room/nwjs/nw.js.svg
    :target: https://gitter.im/openwisp/general
    :alt: Chat

.. image:: https://badge.fury.io/py/openwisp-radius.svg
    :target: http://badge.fury.io/py/openwisp-radius
    :alt: Pypi Version

.. image:: https://pepy.tech/badge/openwisp-radius
    :target: https://pepy.tech/project/openwisp-radius
    :alt: Downloads

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://pypi.org/project/black/
    :alt: code style: black

---

**Need a quick overview?** `Try the OpenWISP Demo
<https://openwisp.org/demo.html>`_.

**OpenWISP RADIUS** provides a web interface to a `freeradius
<https://freeradius.org/>`_ database, a rich `REST HTTP API
<https://openwisp.io/docs/stable/radius/user/rest-api.html>`_ and features
like `user self registration
<https://openwisp.io/docs/stable/radius/user/registration.html>`_, `SMS
verification
<https://openwisp.io/docs/stable/radius/user/rest-api.html#create-sms-token>`_,
`import of users from CSV files
<https://openwisp.io/docs/stable/radius/user/importing_users.html>`_,
`generation of new users for events
<https://openwisp.io/docs/stable/radius/user/generating_users.html>`_,
`social login
<https://openwisp.io/docs/stable/radius/user/social_login.html>`_, and
much more.

It can be used as a standalone application or integrated with the rest of
`OpenWISP <https://openwisp.org>`_. It can also be used as a `base system
or framework on top of which custom tailored solutions can be built
<https://openwisp.io/docs/stable/radius/developer/extending.html>`_.

Documentation
-------------

- `Usage documentation <https://openwisp.io/docs/stable/radius/>`_
- `Developer documentation
  <https://openwisp.io/docs/stable/radius/developer/>`_

Testing
-------

To run tests, use:

```bash
python runtests.py
```

> For Windows users, ensure you are running the command in the VS Code integrated terminal (Ctrl + `) or PowerShell, and use:
>
>     python runtests.py
>
> **Windows Cryptography Issues**: If you encounter DLL load errors related to the cryptography package
> (e.g., "ImportError: DLL load failed while importing _rust"), try these solutions:
>
> - Update pip and cryptography: ``pip install --upgrade pip cryptography``
> - Install Rust if needed: https://www.rust-lang.org/tools/install
> - Try a specific version: ``pip install cryptography==41.0.7``
>
> For detailed troubleshooting steps, refer to the "Troubleshooting Cryptography on Windows" 
> section in the Environment Setup documentation.

Troubleshooting Python Version Issues on Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Windows users running Python 3.9.0 may encounter a ``TypeError: unhashable type: list`` error when running tests. This is a known issue affecting the XML processing libraries used by the test suite. There are two ways to resolve this:

Option 1: Upgrade Python (Recommended)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Upgrade to Python 3.9.2 or later:

1. Download the latest Python version from the `official Python website <https://www.python.org/downloads/>`_
2. Install the new Python version
3. Create a new virtual environment:

   .. code-block:: bash

      # Create a new virtual environment with the upgraded Python
      python -m venv new_venv
      
      # Activate the new environment
      # On Windows Command Prompt:
      new_venv\Scripts\activate
      # On Windows PowerShell:
      .\new_venv\Scripts\Activate.ps1
      
      # Install requirements
      pip install -e .[dev]

Option 2: Pin Dependency Versions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If upgrading Python is not possible, pin the problematic dependencies:

1. Clear pip cache:

   .. code-block:: bash

      pip cache purge

2. Install specific versions of the problematic packages:

   .. code-block:: bash

      pip install elementpath==2.5.0 xmlschema==2.0.0
      
      # Reinstall project dependencies
      pip install -e .[dev]

After applying either solution, run the tests again to verify the issue is resolved.

This will execute all tests and provide a comprehensive report of the results.

Contributing
------------

Please refer to the `OpenWISP contributing guidelines
<http://openwisp.io/docs/developer/contributing.html>`_.

Changelog
---------

See `CHANGES
<https://github.com/openwisp/openwisp-radius/blob/master/CHANGES.rst>`_.

License
-------

See `LICENSE
<https://github.com/openwisp/openwisp-radius/blob/master/LICENSE>`_.

Support
-------

See `OpenWISP Support Channels <http://openwisp.org/support.html>`_.

.. image:: https://raw.githubusercontent.com/openwisp/openwisp2-docs/master/assets/design/openwisp-logo-black.svg
    :target: http://openwisp.org
