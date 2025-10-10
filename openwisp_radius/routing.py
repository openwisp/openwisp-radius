from django.urls import path

from . import consumers

websocket_urlpatterns = [
    path(
        "ws/radius/batch/<uuid:batch_id>/",
        consumers.RadiusBatchConsumer.as_asgi(),
    ),
]
