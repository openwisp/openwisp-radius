from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.core.exceptions import ObjectDoesNotExist

from .utils import load_model


class RadiusBatchConsumer(AsyncJsonWebsocketConsumer):
    def _user_can_access_batch(self, user, batch_id):
        RadiusBatch = load_model("RadiusBatch")
        # Superusers have access to everything,
        if user.is_superuser:
            return RadiusBatch.objects.filter(pk=batch_id).exists()
        # For non-superusers, check their managed organizations
        try:
            RadiusBatch.objects.filter(
                pk=batch_id, organization__in=user.organizations_managed
            ).exists()
            return True
        except ObjectDoesNotExist:
            return False

    async def connect(self):
        self.batch_id = self.scope["url_route"]["kwargs"]["batch_id"]
        self.user = self.scope["user"]
        self.group_name = f"radius_batch_{self.batch_id}"

        if not self.user.is_authenticated or not self.user.is_staff:
            await self.close()
            return

        has_permission = await sync_to_async(self._user_can_access_batch)(
            self.user, self.batch_id
        )

        if not has_permission:
            await self.close()
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def batch_status_update(self, event):
        await self.send_json({"status": event["status"]})
