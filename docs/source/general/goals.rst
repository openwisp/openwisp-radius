=====================
Motivations and Goals
=====================

In this page we explain the goals of this project and the motivations
that led us on this path.

Motivations
-----------

The old version of OpenWISP (which we call OpenWISP 1) had a freeradius module
which provided several interesting features:

- user registration
- account verification with several methods
- user management
- password reset
- basic general statistics
- basic user account page with user's statistics

But it also had important problems:

- it was not written with automated testing in mind, so there was a lot of code which
  the maintainers didn't want to touch because of fear of breaking existing features
- it was not written with an international user-base in mind, it contained a great
  deal of code which was specific to a single country (Italy)
- it was hard to extend, even small changes required changing its core code
- the user management code was implemented in a different way compared to
  other openwisp1 modules, which added a lot of maintenance overhead
- it used outdated dependencies which over time became vulnerable and were hard to replace
- **it did not perform hashing of user passwords**
- the documentation did not explain how to properly install and configure the software

Similar problems were affecting other modules of OpenWISP 1, that's why
over time we got convinced the best thing was to start fresh using best practices
since the start.

Project goals
-------------

The main aim of this project is to offer a web application and documentation
that helps people from all over the world to implement a wifi network
that can use freeradius to authenticate its users, either via captive portal
authentication or WPA2 enterprise, **BUT** this doesn't mean we want to
lock the software to this use case: we want to keep the software generic enough
so it can be useful to implement other use cases that are related to
networking connectivity and network management; **Just keep in mind our main
aim if you plan to contribute to openwisp-radius please**.

Other goals are listed below:

* replace the user management system of OpenWISP 1 by providing a similar feature set
* provide a web interface to manage a freeradius database
* provide abstract models and admin classes that can be imported, extended and reused in third party apps
* provide ways to extend the logic of openwisp-radius without changing its core
* ensure the code is written with an international audience in mind
* maintain a very good automated test suite
* reuse the django user management logic which is very robust and stable
* ensure passwords are hashed with strong algorithms and freeradius can
  authorize/authenticate using these hashes (that's why we recommend using the
  ``rlm_rest`` freeradius module with the REST API of openwisp-radius)
* integrate openwisp-radius with the rest of the openwisp2 ecosystem
* provide good documentation on how to install the project, configure it with
  freeradius and use its most important features
