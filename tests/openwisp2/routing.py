import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application

from openwisp_radius.routing import (
    websocket_urlpatterns as radius_websocket_urlpatterns,
)

ws_routes = list(radius_websocket_urlpatterns)

if os.environ.get("MONITORING_INTEGRATION"):
    from openwisp_controller.routing import get_routes

    ws_routes.extend(get_routes())

application = ProtocolTypeRouter(
    {
        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(URLRouter(ws_routes))
        ),
        "http": get_asgi_application(),
    }
)
