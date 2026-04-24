import swapper
from django.apps.registry import apps
from django.utils import timezone

from ..migrations import migrate_registered_users_multitenant_reverse
from ..utils import load_model
from .mixins import BaseTestCase

RegisteredUser = load_model("RegisteredUser")
Organization = swapper.load_model("openwisp_users", "Organization")
User = swapper.load_model("auth", "User")


class TestMigrations(BaseTestCase):
    def test_multitenant_reverse_updates_weaker_existing_global(self):
        """
        Test that during migration rollback, a weaker existing global
        RegisteredUser is updated with data from a stronger org-scoped
        RegisteredUser instead of being left unchanged.
        """
        user = self._create_user(username="rollback-stronger")
        org1 = self._create_org(name="rollback-org-1", slug="rollback-org-1")
        org2 = self._create_org(name="rollback-org-2", slug="rollback-org-2")
        modified_base = timezone.now()

        # Create a weaker existing global (method="email")
        existing_global = RegisteredUser.objects.create(
            user=user,
            organization=None,
            is_verified=True,
            method="email",
        )
        RegisteredUser.objects.filter(pk=existing_global.pk).update(
            modified=modified_base
        )
        existing_global.refresh_from_db()

        # Create org-scoped email (same strength as global but newer)
        org_email = RegisteredUser.objects.create(
            user=user,
            organization=org1,
            is_verified=True,
            method="email",
        )
        RegisteredUser.objects.filter(pk=org_email.pk).update(
            modified=modified_base + timezone.timedelta(minutes=10)
        )
        org_email.refresh_from_db()

        # Create org-scoped mobile (strongest due to method priority)
        org_mobile = RegisteredUser.objects.create(
            user=user,
            organization=org2,
            is_verified=True,
            method="mobile_phone",
        )
        RegisteredUser.objects.filter(pk=org_mobile.pk).update(
            modified=modified_base - timezone.timedelta(minutes=10)
        )
        org_mobile.refresh_from_db()

        # Rollback: should migrate strongest org-scoped (mobile_phone) to global
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label="openwisp_radius"
        )

        existing_global.refresh_from_db()
        self.assertIsNone(existing_global.organization)
        self.assertEqual(existing_global.method, "mobile_phone")
        self.assertTrue(existing_global.is_verified)
        self.assertEqual(existing_global.modified, org_mobile.modified)
        self.assertEqual(
            RegisteredUser.objects.filter(
                user=user, organization__isnull=False
            ).count(),
            0,
        )

    def test_multitenant_reverse_keeps_stronger_existing_global(self):
        """
        Test that during migration rollback, if an existing global
        RegisteredUser is stronger than all org-scoped candidates,
        it is left unchanged and org-scoped rows are still cleaned up.
        """
        user = self._create_user(username="rollback-global-wins")
        org = self._create_org(name="rollback-org-3", slug="rollback-org-3")
        modified_base = timezone.now()

        # Create a stronger existing global (method="mobile_phone", newer timestamp)
        existing_global = RegisteredUser.objects.create(
            user=user,
            organization=None,
            is_verified=True,
            method="mobile_phone",
        )
        RegisteredUser.objects.filter(pk=existing_global.pk).update(
            modified=modified_base + timezone.timedelta(minutes=10)
        )
        existing_global.refresh_from_db()

        # Create weaker org-scoped (method="social_login", older timestamp)
        org_specific = RegisteredUser.objects.create(
            user=user,
            organization=org,
            is_verified=True,
            method="social_login",
        )
        RegisteredUser.objects.filter(pk=org_specific.pk).update(modified=modified_base)
        org_specific.refresh_from_db()

        # Rollback: global should remain unchanged (stronger), org-scoped deleted
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label="openwisp_radius"
        )

        existing_global.refresh_from_db()
        self.assertIsNone(existing_global.organization)
        self.assertEqual(existing_global.method, "mobile_phone")
        self.assertTrue(existing_global.is_verified)
        self.assertEqual(
            existing_global.modified,
            modified_base + timezone.timedelta(minutes=10),
        )
        self.assertEqual(
            RegisteredUser.objects.filter(
                user=user, organization__isnull=False
            ).count(),
            0,
        )
