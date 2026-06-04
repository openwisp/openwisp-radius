from asgiref.sync import async_to_sync
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from django.contrib.auth import get_user_model
from django.test import TransactionTestCase, override_settings

from openwisp_radius.routing import websocket_urlpatterns
from openwisp_users.models import OrganizationUser

from . import CreateRadiusObjectsMixin

User = get_user_model()


@override_settings(
    CHANNEL_LAYERS={"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
)
class TestRadiusBatchConsumerAuth(CreateRadiusObjectsMixin, TransactionTestCase):
    application = URLRouter(websocket_urlpatterns)

    def _connect(self, path, user):
        communicator = WebsocketCommunicator(self.application, path)
        communicator.scope["user"] = user
        connected = async_to_sync(communicator.connect)()
        return connected

    def test_superuser_can_access_any_batch(self):
        org = self._create_org(name="org", slug="org")
        batch = self._create_radius_batch(
            name="superuser-test",
            strategy="prefix",
            prefix="test-",
            organization=org,
            status="processing",
        )
        admin = self._create_admin()
        connected = self._connect(f"/ws/radius/batch/{batch.pk}/", admin)
        self.assertTrue(connected[0])

    def test_non_staff_superuser_is_rejected(self):
        org = self._create_org(name="org", slug="org")
        batch = self._create_radius_batch(
            name="non-staff-superuser-test",
            strategy="prefix",
            prefix="test-",
            organization=org,
            status="processing",
        )
        superuser = self._create_admin(username="superuser", is_staff=False)
        connected = self._connect(f"/ws/radius/batch/{batch.pk}/", superuser)
        self.assertFalse(connected[0])

    def test_staff_user_managing_org_can_access(self):
        org = self._create_org(name="org", slug="org")
        batch = self._create_radius_batch(
            name="manager-test",
            strategy="prefix",
            prefix="test-",
            organization=org,
            status="processing",
        )
        manager = self._create_administrator(organizations=[org])
        connected = self._connect(f"/ws/radius/batch/{batch.pk}/", manager)
        self.assertTrue(connected[0])

    def test_staff_user_not_managing_org_is_rejected(self):
        org_a = self._create_org(name="org-a", slug="org-a")
        org_b = self._create_org(name="org-b", slug="org-b")
        batch = self._create_radius_batch(
            name="rejection-test",
            strategy="prefix",
            prefix="test-",
            organization=org_a,
            status="processing",
        )
        user = User.objects.create_user(
            username="other-org-staff",
            email="other-org-staff@example.com",
            password="tester",
            is_staff=True,
        )
        OrganizationUser.objects.create(organization=org_b, user=user, is_admin=True)
        connected = self._connect(f"/ws/radius/batch/{batch.pk}/", user)
        self.assertFalse(connected[0])
