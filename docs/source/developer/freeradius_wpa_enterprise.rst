Freeradius Setup for WPA Enterprise (EAP-TTLS-PAP) authentication
=================================================================

This guide explains how to install and configure `freeradius 3
<https://freeradius.org>`_ in order to make it work with `OpenWISP RADIUS
<https://github.com/openwisp/openwisp-radius/>`_ for WPA Enterprise
EAP-TTLS-PAP authentication.

The setup will allow users to authenticate via WiFi WPA Enterprise
networks using their personal username and password of their django user
accounts. Users can either be created manually via the admin interface,
:ref:`generated <generating_users>`, :ref:`imported from CSV
<importing_users>`, or can self register through a web page which makes
use of the :ref:`registration REST API <user_registration>` (like
`openwisp-wifi-login-pages
<https://github.com/openwisp/openwisp-wifi-login-pages>`_).

Prerequisites
-------------

Execute the steps explained in the following sections of the
:ref:`freeradius guide for captive portal authentication
<freeradius_setup_for_captive_portal>`:

    - How to install freeradius 3
    - Enable the configured modules
    - Configure the REST module

Then proceed with the rest of the document.

Freeradius configuration
------------------------

.. _freeradius_site_wpa_enterprise:

Configure the sites
~~~~~~~~~~~~~~~~~~~

Main sites
++++++++++

In this scenario it is necessary to set up one FreeRADIUS site for each
organization you want to support, each FreeRADIUS instance will therefore
need two dedicated ports, one for authentication and one for accounting
and a related inner tunnel configuration.

Let's create the site for an hypotethical organization called org-A.

Don't forget to substitute the occurrences of ``<org_uuid>`` and
``<org_radius_api_token>`` with the UUID & Radius API token of each
organization, refer to the section :ref:`organization_uuid_token` for
finding these values.

.. code-block:: ini

    # /etc/freeradius/sites-enabled/org_a

    server org_a {
        listen {
            type = auth
            ipaddr = *
            # ensure each org has its own port
            port = 1812
            # adjust these as needed
            limit {
              max_connections = 16
              lifetime = 0
              idle_timeout = 30
            }
        }

        listen {
            ipaddr = *
            # ensure each org has its own port
            port = 1813
            type = acct
            limit {}
        }

        # IPv6 configuration skipped for brevity
        # consult the freeradius default configuration if you need
        # to add the IPv6 configuration

        # Substitute the following variables with
        # the organization UUID and RADIUS API Token
        api_token_header = "Authorization: Bearer <org_uuid> <org_radius_api_token>"

        authorize {
            eap-org_a {
               ok = return
            }

            update control { &REST-HTTP-Header += "${...api_token_header}" }
            rest
        }

        authenticate {
            Auth-Type eap-org_a {
                eap-org_a
            }
        }

        post-auth {
            update control { &REST-HTTP-Header += "${...api_token_header}" }
            rest

            Post-Auth-Type REJECT {
                update control { &REST-HTTP-Header += "${....api_token_header}" }
                rest
            }
        }

        accounting {
            update control { &REST-HTTP-Header += "${...api_token_header}" }
            rest
        }
    }

Please also ensure that ``acct_unique`` is present in the
``pre-accounting`` section:

.. code-block:: ini

    preacct {
        # ...
        acct_unique
        # ...
    }

Inner tunnels
+++++++++++++

You will need to set up one inner tunnel for each organization too.

Following the example for a hypotetical organization named org-A:

.. code-block:: ini

    # /etc/freeradius/sites-enabled/inner-tunnel

    server inner-tunnel_org_a {
        listen {
            ipaddr = 127.0.0.1
            # each org will need a dedicated port for their inner tunnel
            port = 18120
            type = auth
        }

        api_token_header = "Authorization: Bearer <org_uuid> <org_radius_api_token>"

        authorize {
            filter_username
            update control { &REST-HTTP-Header += "${...api_token_header}" }
            rest

            eap-org_a {
                ok = return
            }

            expiration
            logintime

            pap
        }

        authenticate {
            Auth-Type PAP {
                pap
            }

            Auth-Type CHAP {
                chap
            }

            Auth-Type MS-CHAP {
                mschap
            }
            eap-org_a
        }

        session {}

        post-auth {
        }

        pre-proxy {}
        post-proxy {
            eap-org_a
        }
    }

Configure the EAP modules
~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

    Keep in mind these are basic sample configurations, once you get it
    working feel free to tweak it to make it more secure and fully
    featured.

You will need to set up one EAP module instance for each organization too.

Following the example for a hypotetical organization named org-A:

.. code-block:: ini

    eap eap-org_a {
        default_eap_type = ttls
        timer_expire = 60
        ignore_unknown_eap_types = no
        cisco_accounting_username_bug = no
        max_sessions = ${max_requests}

        tls-config tls-common {
            # make sure to have a valid SSL certificate for production usage
            private_key_password = whatever
            private_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
            certificate_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
            ca_file = /etc/ssl/certs/ca-certificates.crt
            dh_file = ${certdir}/dh
            ca_path = ${cadir}
            cipher_list = "DEFAULT"
            cipher_server_preference = no
            ecdh_curve = "prime256v1"

            cache {
                enable = no
            }

            ocsp {
                enable = no
                override_cert_url = yes
                url = "http://127.0.0.1/ocsp/"
            }
        }

        ttls {
            tls = tls-common
            default_eap_type = pap
            copy_request_to_tunnel = yes
            use_tunneled_reply = yes
            virtual_server = "inner-tunnel_org_a"
        }
    }

Repeating the steps for more organizations
------------------------------------------

Let's say you don't have only the hypotetical org-A in your system but
more organizations, in that case you simply have to repeat the steps
explained in the previous sections, substituting the occurrences of org-A
with the names of the other organizations.

So if you have an organization named ACME Systems, copy the files and
substitute the occurrences ``org_a`` with ``acme_systems``.

Final steps
-----------

Once the configurations are ready, you should :ref:`restart freeradius
<restart_freeradius>` and :ref:`then test/troubleshoot/debug your setup
<debugging>`.

Implementing other EAP scenarios
--------------------------------

Implementing other setups like EAP-TLS requires additional development
effort.

`OpenWISP Controller <https://github.com/openwisp/openwisp-controller>`_
already supports x509 certificates, so it would be a matter of integrating
the `django-x509 <https://github.com/openwisp/django-x509>`_ module into
OpenWISP RADIUS and then implement mechanisms for the users to securely
download their certificates.

If you're interested in this feature, let us know via the :ref:`support
channels <support>`.
