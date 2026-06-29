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

- Use JSON-encoded messages on the wire.
- Require an authenticated staff user via session-based authentication.
- Push real-time updates after the connection is established.
- Do not accept client messages: any data sent from the client is ignored.

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

A user is authorized only if authenticated and marked as staff, and one of
the following conditions is true:

- The user is a superuser, OR
- The user is an organization manager for the organization that owns the
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

Client Message
++++++++++++++

The endpoint does not expose a request/response message for retrieving the
current state on demand. Messages are delivered when batch processing
finishes.

.. warning::

    Any message sent by the client is ignored.

Real-time Updates
+++++++++++++++++

After the connection is established, the client does not need to send any
messages. The server pushes exactly **one** message when batch processing
finishes (either successfully or with an error).

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
3. When batch processing finishes, the server sends one JSON message
   containing the terminal status.
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
