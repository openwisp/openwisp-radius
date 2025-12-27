import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from django.core.asgi import get_asgi_application
from openwisp_notifications.websockets.routing import (
    get_routes as get_notification_routes,
)

from openwisp_radius.routing import (
    websocket_urlpatterns as radius_websocket_urlpatterns,
)

ws_routes = radius_websocket_urlpatterns + get_notification_routes()

if os.environ.get("MONITORING_INTEGRATION"):
    from openwisp_controller.routing import get_routes as get_controller_routes

    ws_routes.extend(get_controller_routes())

application = ProtocolTypeRouter(
    {
        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(URLRouter(ws_routes))
        ),
        "http": get_asgi_application(),
    }
)
