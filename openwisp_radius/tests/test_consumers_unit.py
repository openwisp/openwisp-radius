import os
from unittest.mock import AsyncMock, MagicMock

import swapper
from channels.db import database_sync_to_async
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TransactionTestCase

from openwisp_users.tests.utils import TestOrganizationMixin

User = get_user_model()


def load_model(model):
    return swapper.load_model("openwisp_radius", model)


class CreateRadiusObjectsMixin(TestOrganizationMixin):
    def _create_radius_batch(self, **kwargs):
        RadiusBatch = load_model("RadiusBatch")
        if "organization" not in kwargs:
            kwargs["organization"] = self._get_org()
        options = {
            "strategy": "prefix",
            "prefix": "test",
            "name": "test-batch",
        }
        options.update(kwargs)
        rb = RadiusBatch(**options)
        rb.full_clean()
        rb.save()
        return rb

    def _get_org(self, org_name="test org"):
        OrganizationRadiusSettings = load_model("OrganizationRadiusSettings")
        organization = super()._get_org(org_name)
        OrganizationRadiusSettings.objects.get_or_create(
            organization_id=organization.pk
        )
        return organization


class TestRadiusBatchConsumerUnit(CreateRadiusObjectsMixin, TransactionTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        os.makedirs(settings.MEDIA_ROOT, exist_ok=True)

    def setUp(self):
        super().setUp()
        from ..consumers import RadiusBatchConsumer

        self.ConsumerClass = RadiusBatchConsumer
        self.org = self._create_org()
        self.user = self._create_user(is_staff=True)
        OrganizationUser = swapper.load_model("openwisp_users", "OrganizationUser")
        OrganizationUser.objects.create(
            user=self.user, organization=self.org, is_admin=True
        )
        self.batch = self._create_radius_batch(organization=self.org)

    async def test_connect_authenticated_staff_with_permission(self):
        consumer = self.ConsumerClass()
        consumer.scope = {
            "url_route": {"kwargs": {"batch_id": str(self.batch.pk)}},
            "user": self.user,
        }
        consumer.channel_layer = AsyncMock()
        consumer.channel_name = "test_channel"
        consumer.accept = AsyncMock()
        consumer.close = AsyncMock()
        await consumer.connect()
        consumer.accept.assert_called_once()
        consumer.channel_layer.group_add.assert_called_once()
        call_args = consumer.channel_layer.group_add.call_args
        self.assertEqual(call_args[0][0], f"radius_batch_{self.batch.pk}")
        self.assertEqual(call_args[0][1], "test_channel")

    async def test_connect_unauthenticated(self):
        consumer = self.ConsumerClass()
        consumer.scope = {
            "url_route": {"kwargs": {"batch_id": str(self.batch.pk)}},
            "user": MagicMock(is_authenticated=False),
        }
        consumer.close = AsyncMock()
        await consumer.connect()
        consumer.close.assert_called_once()

    async def test_connect_authenticated_non_staff(self):
        user = await database_sync_to_async(self._create_user)(
            is_staff=False, username="regular_user", email="regular@example.com"
        )
        consumer = self.ConsumerClass()
        consumer.scope = {
            "url_route": {"kwargs": {"batch_id": str(self.batch.pk)}},
            "user": user,
        }
        consumer.close = AsyncMock()
        await consumer.connect()
        consumer.close.assert_called_once()

    async def test_connect_wrong_organization(self):
        org2 = await database_sync_to_async(self._create_org)(name="other org")
        batch2 = await database_sync_to_async(self._create_radius_batch)(
            organization=org2
        )
        consumer = self.ConsumerClass()
        consumer.scope = {
            "url_route": {"kwargs": {"batch_id": str(batch2.pk)}},
            "user": self.user,
        }
        consumer.close = AsyncMock()
        await consumer.connect()
        consumer.close.assert_called_once()

    async def test_connect_batch_not_found(self):
        import uuid

        fake_uuid = str(uuid.uuid4())

        consumer = self.ConsumerClass()
        consumer.scope = {
            "url_route": {"kwargs": {"batch_id": fake_uuid}},
            "user": self.user,
        }
        consumer.close = AsyncMock()
        await consumer.connect()
        consumer.close.assert_called_once()

    async def test_batch_status_update(self):
        consumer = self.ConsumerClass()
        consumer.send_json = AsyncMock()
        event = {"status": "processing"}
        await consumer.batch_status_update(event)
        consumer.send_json.assert_called_once_with({"status": "processing"})

    async def test_disconnect(self):
        consumer = self.ConsumerClass()
        consumer.channel_layer = AsyncMock()
        consumer.channel_name = "test_channel"
        consumer.group_name = f"radius_batch_{self.batch.pk}"
        await consumer.disconnect(1000)
        consumer.channel_layer.group_discard.assert_called_once()
        call_args = consumer.channel_layer.group_discard.call_args
        self.assertEqual(call_args[0][0], f"radius_batch_{self.batch.pk}")
        self.assertEqual(call_args[0][1], "test_channel")
