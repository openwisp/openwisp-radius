============
Contributing
============

Thank you for taking the time to contribute to openwisp-radius, please read the
`guide for contributing to openwisp repositories <http://openwisp.io/docs/developer/contributing.html>`_.

Follow these guidelines to speed up the process.

.. contents:: **Table of Contents**:
  :backlinks: none
  :depth: 3

.. note::
    **In order to have your contribution accepted faster**, please read the
    `OpenWISP contributing guidelines <http://openwisp.io/docs/developer/contributing.html>`_ and make sure to follow its guidelines.

Setup
-----

Once you have chosen an issue to work on, `setup your machine for development
<./setup.html#installing-for-development>`_

Ensure test coverage does not decrease
--------------------------------------

First of all, install the test requirements:

.. code-block:: shell

    workon radius  # activate virtualenv
    pip install --no-cache-dir -U -r requirements-test.txt

When you introduce changes, ensure test coverage is not decreased with:

.. code-block:: shell

    coverage run --source=openwisp_radius runtests.py

Follow style conventions
------------------------

First of all, install the test requirements:

.. code-block:: shell

    workon radius  # activate virtualenv
    pip install --no-cache-dir -U -r requirements-test.txt
    npm install -g jslint

Before committing your work check that your changes are not breaking
our `coding style conventions <https://openwisp.io/docs/developer/contributing.html#coding-style-conventions>`_:

.. code-block:: shell

    # reformat the code according to the conventions
    openwisp-qa-format
    # run QA checks
    ./run-qa-checks

For more information, please see:

- `OpenWISP Coding Style Conventions <https://openwisp.io/docs/developer/contributing.html#coding-style-conventions>`_

Update the documentation
------------------------

If you introduce new features or change existing documented behavior,
please remember to update the documentation!

The documentation is located in the ``/docs`` directory
of the repository.

To do work on the docs, proceed with the following steps:

.. code-block:: shell

    workon radius  # activate virtualenv
    pip install sphinx
    cd docs
    make html

Send pull request
-----------------

Now is time to push your changes to github and open a `pull request
<https://github.com/openwisp/openwisp-radius/pulls>`_!
