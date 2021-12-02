===============
openwisp-radius
===============

.. image:: https://travis-ci.org/openwisp/openwisp-radius.svg?branch=master
   :target: https://travis-ci.org/openwisp/openwisp-radius
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

.. image:: images/demo_radius.gif
   :alt: Feature Highlights


**OpenWISP-RADIUS** is Django reusable app that provides an admin interface to a
`freeradius <https://freeradius.org/>`_ database.

.. note::
   If you're building a public wifi service, we suggest
   to take a look at `openwisp-wifi-login-pages <https://github.com/openwisp/openwisp-wifi-login-pages>`_,
   which is built to work with openwisp-radius.

.. image:: https://raw.githubusercontent.com/openwisp/openwisp2-docs/master/assets/design/openwisp-logo-black.svg
   :target: http://openwisp.org

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   /developer/setup
   /developer/freeradius
   /user/settings
   /user/management_commands
   /user/importing_users
   /user/generating_users
   /user/enforcing_limits
   /user/registration
   /user/social_login
   /user/saml
   /user/api
   /developer/signals
   /developer/how_to_extend
   /developer/captive_portal_mock.rst
   /general/support
   /developer/contributing
   /general/goals
