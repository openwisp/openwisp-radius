from asgiref.sync import async_to_sync
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.test import TransactionTestCase
from django.urls import re_path

from openwisp_users.tests.utils import TestOrganizationMixin

from ..consumers import RadiusBatchConsumer
from ..utils import load_model
from . import CreateRadiusObjectsMixin

User = get_user_model()
RadiusBatch = load_model("RadiusBatch")

application = URLRouter(
    [
        re_path(
            r"^ws/radius/batch/(?P<batch_id>[^/]+)/$",
            RadiusBatchConsumer.as_asgi(),
        ),
    ]
)


class TestRadiusBatchConsumer(
    CreateRadiusObjectsMixin, TestOrganizationMixin, TransactionTestCase
):

    TEST_PASSWORD = "test_password"  # noqa: S105

    def _create_test_data(self):
        org = self._create_org()
        user = self._create_admin(password=self.TEST_PASSWORD)
        batch = self._create_radius_batch(
            name="test-batch",
            strategy="prefix",
            prefix="test-",
            organization=org,
        )
        return org, user, batch

    def test_websocket_connect_superuser(self):
        _, user, batch = self._create_test_data()

        async def test():
            communicator = WebsocketCommunicator(
                application,
                f"/ws/radius/batch/{batch.pk}/",
            )
            communicator.scope["user"] = user
            communicator.scope["url_route"] = {"kwargs": {"batch_id": str(batch.pk)}}

            connected, _ = await communicator.connect()
            assert connected is True
            await communicator.disconnect()

        async_to_sync(test)()

    def test_websocket_connect_staff_with_permission(self):
        org, _, batch = self._create_test_data()
        staff_user = self._create_administrator(
            organizations=[org], password=self.TEST_PASSWORD
        )

        async def test():
            communicator = WebsocketCommunicator(
                application,
                f"/ws/radius/batch/{batch.pk}/",
            )
            communicator.scope["user"] = staff_user
            communicator.scope["url_route"] = {"kwargs": {"batch_id": str(batch.pk)}}

            connected, _ = await communicator.connect()
            assert connected is True
            await communicator.disconnect()

        async_to_sync(test)()

    def test_websocket_reject_unauthenticated(self):
        _, _, batch = self._create_test_data()

        async def test():
            communicator = WebsocketCommunicator(
                application,
                f"/ws/radius/batch/{batch.pk}/",
            )
            from django.contrib.auth.models import AnonymousUser

            communicator.scope["user"] = AnonymousUser()
            communicator.scope["url_route"] = {"kwargs": {"batch_id": str(batch.pk)}}

            connected, _ = await communicator.connect()
            assert connected is False

        async_to_sync(test)()

    def test_websocket_reject_non_staff(self):
        _, _, batch = self._create_test_data()
        regular_user = self._create_user(is_staff=False, password=self.TEST_PASSWORD)

        async def test():
            communicator = WebsocketCommunicator(
                application,
                f"/ws/radius/batch/{batch.pk}/",
            )
            communicator.scope["user"] = regular_user
            communicator.scope["url_route"] = {"kwargs": {"batch_id": str(batch.pk)}}

            connected, _ = await communicator.connect()
            assert connected is False

        async_to_sync(test)()

    def test_websocket_reject_no_permission(self):
        _, _, batch = self._create_test_data()

        staff_user = self._create_user(is_staff=True, password=self.TEST_PASSWORD)

        async def test():
            communicator = WebsocketCommunicator(
                application,
                f"/ws/radius/batch/{batch.pk}/",
            )
            communicator.scope["user"] = staff_user
            communicator.scope["url_route"] = {"kwargs": {"batch_id": str(batch.pk)}}

            connected, _ = await communicator.connect()
            assert connected is False

        async_to_sync(test)()

    def test_websocket_group_connection(self):
        _, user, batch = self._create_test_data()

        async def test():
            communicator = WebsocketCommunicator(
                application,
                f"/ws/radius/batch/{batch.pk}/",
            )
            communicator.scope["user"] = user
            communicator.scope["url_route"] = {"kwargs": {"batch_id": str(batch.pk)}}

            connected, _ = await communicator.connect()
            assert connected is True
            await communicator.disconnect()

        async_to_sync(test)()

    def test_batch_status_update(self):
        _, user, batch = self._create_test_data()

        async def test():
            communicator = WebsocketCommunicator(
                application,
                f"/ws/radius/batch/{batch.pk}/",
            )
            communicator.scope["user"] = user
            communicator.scope["url_route"] = {"kwargs": {"batch_id": str(batch.pk)}}

            connected, _ = await communicator.connect()
            assert connected is True

            from channels.layers import get_channel_layer

            channel_layer = get_channel_layer()

            await channel_layer.group_send(
                f"radius_batch_{batch.pk}",
                {"type": "batch_status_update", "status": "processing"},
            )

            response = await communicator.receive_json_from()
            assert response == {"status": "processing"}

            await communicator.disconnect()

        async_to_sync(test)()

    def test_disconnect_cleanup(self):
        _, user, batch = self._create_test_data()

        async def test():
            communicator = WebsocketCommunicator(
                application,
                f"/ws/radius/batch/{batch.pk}/",
            )
            communicator.scope["user"] = user
            communicator.scope["url_route"] = {"kwargs": {"batch_id": str(batch.pk)}}

            connected, _ = await communicator.connect()
            assert connected is True

            await communicator.disconnect()

            from channels.layers import get_channel_layer

            channel_layer = get_channel_layer()

            await channel_layer.group_send(
                f"radius_batch_{batch.pk}",
                {"type": "batch_status_update", "status": "completed"},
            )

            assert await communicator.receive_nothing() is True

        async_to_sync(test)()

    def test_user_can_access_batch_method(self):
        _, user, batch = self._create_test_data()
        consumer = RadiusBatchConsumer()

        self.assertTrue(consumer._user_can_access_batch(user, batch.pk))

        org = self._create_org(name="test-org-2", slug="test-org-2")
        staff_user = self._create_administrator(
            organizations=[org],
            password=self.TEST_PASSWORD,
            username="staff_user_2",
            email="staff2@example.com",
        )
        batch2 = self._create_radius_batch(
            name="test2",
            organization=org,
            strategy="prefix",
            prefix="test-prefix-2",
        )
        self.assertTrue(consumer._user_can_access_batch(staff_user, batch2.pk))

        other_org = self._create_org(name="other", slug="other")
        other_user = self._create_administrator(
            organizations=[other_org],
            password=self.TEST_PASSWORD,
            username="other_user",
            email="other@example.com",
        )
        self.assertFalse(consumer._user_can_access_batch(other_user, batch2.pk))

    def test_invalid_batch_id(self):
        _, user, _ = self._create_test_data()

        async def test():
            invalid_batch_id = "00000000-0000-0000-0000-000000000000"
            communicator = WebsocketCommunicator(
                application,
                f"/ws/radius/batch/{invalid_batch_id}/",
            )
            communicator.scope["user"] = user
            communicator.scope["url_route"] = {"kwargs": {"batch_id": invalid_batch_id}}

            connected, _ = await communicator.connect()
            assert connected is False

        async_to_sync(test)()

    def test_user_can_access_batch_with_invalid_uuid(self):
        _, user, _ = self._create_test_data()
        consumer = RadiusBatchConsumer()

        result = consumer._user_can_access_batch(
            user, "00000000-0000-0000-0000-000000000000"
        )
        self.assertFalse(result)
