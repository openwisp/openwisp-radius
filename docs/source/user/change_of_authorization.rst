.. _change_of_authorization:

Change of Authorization (CoA)
=============================

.. important::

    The *Change of Authorization (CoA)* is disabled by default.

    In order to enable this feature you have it enable it via :ref:`global
    setting or from the admin interface <coa_enabled_setting>`.

The openwisp-radius module supports the Change of Authorization (CoA)
specification of the RADIUS protocol described in `RFC 5176
<https://datatracker.ietf.org/doc/rfc5176/>`_.

Whenever the *RADIUS Group* of a user is changed, openwisp-radius updates
the NAS with the user's latest RADIUS Attributes. This is achieved by
sending CoA RADIUS packet to NAS for all open RADIUS sessions of the user.
This allows enforcing RADIUS limits without requiring the user to
re-authenticate with the NAS.

The CoA RADIUS packet contains the RADIUS Attributes defined in the new
*RADIUS Group* of the user. If the new *RADIUS Group* does not specify any
attributes, the CoA RADIUS packet will unset the attributes set by the
previous *RADIUS Group*.

Consider the following example with two *RADIUS Groups*:

===================== ===================================================
**RADIUS Group Name** **RADIUS Group Checks**
**users**             ============================= ================
                      **Attribute**                 **Value**
                      ``Max-Daily-Session-Traffic`` ``:=3000000000``
                      ``Max-Daily-Session``         ``:=10800``
                      ============================= ================
**power-users**       *Note: This group intentionally does not define any
                      limits.*
===================== ===================================================

A user, Jane is assigned ``users`` *RADIUS Group* and is currently using
the network, i.e. has an open RADIUS session. The administrator of the
system decided to upgrade the *RADIUS Group* of Jane to ``power-users``,
allowing Jane to use the network without any limits. Without CoA, Jane
will have to logout of the captive portal (NAS) and log-in again to browse
the network without any limits. But when CoA is enabled in
openwisp-radius, openwisp-radius will update the NAS with the limits
defined in Jane's new RADIUS Group. In this case, openwisp-radius will
tell the NAS to unset the limits that were configured by the previous
RADIUS Group.

If the system administrators later decided to downgrade the *RADIUS Group*
of Jane to ``users``, hence enforcing limits to the usage of the network,
openwisp-radius will update the NAS with the limits defined for the
``users`` group for all active RADIUS sessions if CoA is enabled in
openwisp-radius.
