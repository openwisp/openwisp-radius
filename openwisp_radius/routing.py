from django.urls import path
from openwisp_notifications.websockets.routing import (
    get_routes as get_notification_routes,
)

from . import consumers

websocket_urlpatterns = [
    path(
        "ws/radius/batch/<uuid:batch_id>/",
        consumers.RadiusBatchConsumer.as_asgi(),
    ),
] + get_notification_routes()
