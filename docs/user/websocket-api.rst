.. _radius_websocket_api:

WebSocket API Reference
=======================

.. contents:: **Table of contents**:
    :depth: 2
    :local:

Overview
--------

The WebSocket API provides real-time status updates for batch user
creation operations.

When a batch is processed asynchronously (i.e., the number of users to
generate or import meets or exceeds
:ref:`OPENWISP_RADIUS_BATCH_ASYNC_THRESHOLD
<openwisp_radius_batch_async_threshold>`), the Django admin interface
automatically connects to the relevant endpoint to receive live status
updates without polling.

All endpoints:

- Use JSON messages.
- Require an authenticated staff user (session-based authentication).
- Push real-time updates from the server; no client message is required
  after the connection is established.

Authentication and Authorization
--------------------------------

All WebSocket endpoints require an authenticated user.

A connection is accepted only if the user is authorized to access the
requested resource. The connection is closed immediately if authorization
fails.

Authentication uses the Django session cookie via ``AuthMiddlewareStack``
(from ``channels.auth``). DRF token authentication is not supported for
WebSocket connections.

The ``Origin`` header is validated against ``ALLOWED_HOSTS`` via
``AllowedHostsOriginValidator``. Cross-origin connections from untrusted
hosts are rejected.

A user is authorized if:

- The user is a superuser, OR
- The user:

  - Is authenticated and marked as staff, AND
  - Is an organization manager for the organization that owns the
    requested batch.

If any check fails, the server closes the connection without sending any
message.

Connection Endpoints
--------------------

1. Batch User Creation Status
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint delivers real-time status updates for a single batch user
creation operation.

Connection URL
++++++++++++++

::

    wss://<host>/ws/radius/batch/<batch-id>/

- ``<host>``: the hostname and port of the OpenWISP instance.
- ``<batch-id>``: the UUID of the ``RadiusBatch`` object to monitor.

.. note::

    Use ``wss://`` for HTTPS deployments and ``ws://`` for plain HTTP
    (development only). Never use ``ws://`` in production.

Scope
+++++

A single batch user creation operation identified by its UUID.

Server-Pushed Messages
++++++++++++++++++++++

After the connection is established, the client does not need to send any
messages. The server pushes exactly **one** message when batch processing
finishes (either successfully or with an error).

Message type: ``batch_status_update``

.. code-block:: javascript

    {
        "status": "<status>"
    }

The ``status`` field contains one of the following values:

.. list-table::
    :header-rows: 1

    - - Value
      - Description
    - - ``"pending"``
      - The batch has been created but processing has not yet started.
        This value is not sent via WebSocket; it is visible only through
        the REST API or admin interface.
    - - ``"processing"``
      - The batch is currently being processed. This value is not sent via
        WebSocket; it is the status visible when the admin page is opened
        and the WebSocket connection is established.
    - - ``"completed"``
      - Batch processing finished successfully. This is a terminal status.
    - - ``"failed"``
      - Batch processing encountered an error. This is a terminal status.

.. note::

    The server sends exactly one message per connection, always with a
    terminal status (``"completed"`` or ``"failed"``). The client should
    close the connection after receiving it.

Connection Lifecycle
++++++++++++++++++++

1. The client connects to the endpoint with the batch UUID in the URL.
2. If the user is authorized, the connection is accepted and the client is
   added to the channel group ``radius_batch_<batch-id>``.
3. When batch processing finishes, the server sends one
   ``batch_status_update`` message containing the terminal status.
4. The client should close the connection upon receiving ``"completed"``
   or ``"failed"``.
5. On disconnect, the client is removed from the channel group.

Example Client (JavaScript)
+++++++++++++++++++++++++++

Example based on the admin interface implementation:

.. code-block:: javascript

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = protocol + "//" + window.location.host
                  + "/ws/radius/batch/<batch-id>/";
    const socket = new WebSocket(wsUrl);

    socket.onmessage = function (event) {
        const data = JSON.parse(event.data);
        if (data.status === "completed" || data.status === "failed") {
            socket.close();
        }
    };

    socket.onclose = function (event) {
        console.log("RadiusBatch status socket closed.");
    };

Replace ``<batch-id>`` with the UUID of the batch object.

Deployment Requirements
-----------------------

WebSocket support requires server-side configuration beyond the default
Django setup. The following components must be in place.

ASGI Server
~~~~~~~~~~~

Django's default WSGI server does not support WebSockets. You must use an
ASGI-compatible server such as `Daphne
<https://github.com/django/daphne>`_.

Install Daphne and add it as the **first entry** in ``INSTALLED_APPS`` so
that Django uses it as the ASGI server:

.. code-block:: python

    INSTALLED_APPS = [
        "daphne",
        # ... other apps
        "channels",
        # ...
    ]

``ASGI_APPLICATION``
~~~~~~~~~~~~~~~~~~~~

Point Django to your project's ASGI application, which must include the
Channels routing:

.. code-block:: python

    ASGI_APPLICATION = "your_project.routing.application"

``CHANNEL_LAYERS``
~~~~~~~~~~~~~~~~~~

A Redis-backed channel layer is required for production deployments.
Install ``channels_redis`` and configure it:

.. code-block:: python

    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {
                "hosts": [("localhost", 6379)],
            },
        }
    }

WebSocket Routing
~~~~~~~~~~~~~~~~~

Import ``openwisp_radius.routing.websocket_urlpatterns`` and include it in
your project's ``URLRouter``. Example ASGI routing module:

.. code-block:: python

    from channels.auth import AuthMiddlewareStack
    from channels.routing import ProtocolTypeRouter, URLRouter
    from channels.security.websocket import AllowedHostsOriginValidator
    from django.core.asgi import get_asgi_application

    from openwisp_radius.routing import websocket_urlpatterns

    application = ProtocolTypeRouter(
        {
            "websocket": AllowedHostsOriginValidator(
                AuthMiddlewareStack(URLRouter(websocket_urlpatterns))
            ),
            "http": get_asgi_application(),
        }
    )
