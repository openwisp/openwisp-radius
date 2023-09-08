RADIUS
======

.. seealso::

    **Source code**: `github.com/openwisp/openwisp-radius
    <https://github.com/openwisp/openwisp-radius>`_.

OpenWISP RADIUS is available since OpenWISP 22.05 and provides many
features aimed at public WiFi services.

For a full introduction please refer to :doc:`user/intro`.

The following diagram illustrates the role of the RADIUS module within the
OpenWISP architecture.

.. figure:: /images/architecture/v2/architecture-v2-openwisp-radius.png
    :target: ../_images/architecture-v2-openwisp-radius.png
    :align: center
    :alt: OpenWISP Architecture: Radius module

    **OpenWISP Architecture: highlighted radius module**

.. important::

    For an enhanced viewing experience, open the image above in a new
    browser tab.

    Refer to :doc:`/general/architecture` for more information.

.. toctree::
    :caption: RADIUS Module Usage Docs
    :maxdepth: 1

    user/intro.rst
    user/registration.rst
    user/generating_users.rst
    user/importing_users.rst
    user/social_login.rst
    user/saml.rst
    user/enforcing_limits.rst
    user/change_of_authorization.rst
    user/radius_monitoring
    user/management_commands.rst
    user/rest-api.rst
    user/settings.rst

.. toctree::
    :caption: RADIUS Module Developer Docs
    :maxdepth: 2

    Developer Docs Index <developer/index.rst>

Deploy instructions
-------------------

See :ref:`Enabling the RADIUS module on the OpenWISP ansible role
documentation <ansible_enabling_radius_module>`.

Alternatively you can set it up manually by following these guides:

.. toctree::
    :maxdepth: 1

    deploy/freeradius
    deploy/freeradius_wpa_enterprise

This module is also available in :doc:`docker-openwisp </docker/index>`
although its usage is not recommended for production usage yet, unless the
reader is willing to invest effort in adapting the docker images and
configurations to overcome any roadblocks encountered.
