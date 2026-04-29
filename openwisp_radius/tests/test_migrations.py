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
        expected_modified = modified_base - timezone.timedelta(minutes=10)
        RegisteredUser.objects.filter(pk=org_mobile.pk).update(
            modified=expected_modified
        )
        org_mobile.refresh_from_db()

        # Rollback: should migrate strongest org-scoped (mobile_phone) to global
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label="openwisp_radius"
        )

        existing_global.refresh_from_db()
        self.assertEqual(existing_global.organization, None)
        self.assertEqual(existing_global.method, "mobile_phone")
        self.assertEqual(existing_global.is_verified, True)
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
        self.assertFalse(
            RegisteredUser.objects.filter(
                user=user, organization__isnull=False
            ).exists()
        )

    def test_multitenant_reverse_creates_global_when_missing(self):
        """
        Test that if no global record exists, a new global record is created
        from the strongest org-scoped record.
        """
        user = self._create_user(username="no-global-user")
        org1 = self._create_org(name="no-global-org-1", slug="no-global-org-1")
        org2 = self._create_org(name="no-global-org-2", slug="no-global-org-2")
        modified_base = timezone.now()
        # Verify no global exists
        self.assertFalse(
            RegisteredUser.objects.filter(user=user, organization__isnull=True).exists()
        )
        # Create weaker org-scoped (email, unverified)
        org_email = RegisteredUser.objects.create(
            user=user,
            organization=org1,
            is_verified=False,
            method="email",
        )
        RegisteredUser.objects.filter(pk=org_email.pk).update(modified=modified_base)
        # Create stronger org-scoped (mobile_phone, verified)
        org_mobile = RegisteredUser.objects.create(
            user=user,
            organization=org2,
            is_verified=True,
            method="mobile_phone",
        )
        expected_modified = modified_base - timezone.timedelta(minutes=10)
        RegisteredUser.objects.filter(pk=org_mobile.pk).update(
            modified=expected_modified
        )
        org_mobile.refresh_from_db()
        # Rollback: should create global from strongest org record
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label="openwisp_radius"
        )
        # Verify global created with strongest record's data
        global_record = RegisteredUser.objects.get(user=user, organization__isnull=True)
        self.assertEqual(global_record.is_verified, True)
        self.assertEqual(global_record.method, "mobile_phone")
        self.assertEqual(global_record.modified, expected_modified)
        # Verify all org-scoped records deleted
        self.assertFalse(
            RegisteredUser.objects.filter(
                user=user, organization__isnull=False
            ).exists()
        )

    def test_multitenant_reverse_verified_wins_over_method(self):
        """
        Test that is_verified=True always wins over False, regardless of method
        strength.
        """
        user = self._create_user(username="verified-wins-user")
        org1 = self._create_org(name="verified-org-1", slug="verified-org-1")
        org2 = self._create_org(name="verified-org-2", slug="verified-org-2")
        modified_base = timezone.now()
        # Strong method but unverified
        org_strong_method = RegisteredUser.objects.create(
            user=user,
            organization=org1,
            is_verified=False,
            method="mobile_phone",
        )
        RegisteredUser.objects.filter(pk=org_strong_method.pk).update(
            modified=modified_base
        )
        # Weaker method but verified
        org_weak_method = RegisteredUser.objects.create(
            user=user,
            organization=org2,
            is_verified=True,
            method="email",
        )
        RegisteredUser.objects.filter(pk=org_weak_method.pk).update(
            modified=modified_base - timezone.timedelta(minutes=10)
        )
        org_weak_method.refresh_from_db()
        # Rollback: verified should win despite weaker method
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label="openwisp_radius"
        )
        global_record = RegisteredUser.objects.get(user=user, organization__isnull=True)
        self.assertEqual(global_record.is_verified, True)
        self.assertEqual(global_record.method, "email")

    def test_multitenant_reverse_multiple_org_competition(self):
        """
        Test correct ordering when multiple org-scoped records compete.
        """
        user = self._create_user(username="multi-org-user")
        org1 = self._create_org(name="multi-org-1", slug="multi-org-1")
        org2 = self._create_org(name="multi-org-2", slug="multi-org-2")
        org3 = self._create_org(name="multi-org-3", slug="multi-org-3")
        modified_base = timezone.now()
        # Org1: unverified, empty method, oldest
        org1_record = RegisteredUser.objects.create(
            user=user,
            organization=org1,
            is_verified=False,
            method="",
        )
        RegisteredUser.objects.filter(pk=org1_record.pk).update(
            modified=modified_base - timezone.timedelta(minutes=30)
        )
        # Org2: verified, email method, middle timestamp
        org2_record = RegisteredUser.objects.create(
            user=user,
            organization=org2,
            is_verified=True,
            method="email",
        )
        RegisteredUser.objects.filter(pk=org2_record.pk).update(
            modified=modified_base - timezone.timedelta(minutes=15)
        )
        org2_record.refresh_from_db()
        # Org3: verified, mobile_phone method, newest (should win)
        org3_record = RegisteredUser.objects.create(
            user=user,
            organization=org3,
            is_verified=True,
            method="mobile_phone",
        )
        expected_modified = modified_base
        RegisteredUser.objects.filter(pk=org3_record.pk).update(
            modified=expected_modified
        )
        org3_record.refresh_from_db()
        # Rollback: org3 should win (verified + strongest method)
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label="openwisp_radius"
        )
        global_record = RegisteredUser.objects.get(user=user, organization__isnull=True)
        self.assertTrue(global_record.is_verified)
        self.assertEqual(global_record.method, "mobile_phone")
        self.assertEqual(global_record.modified, expected_modified)
        # Only one record should exist
        self.assertEqual(RegisteredUser.objects.filter(user=user).count(), 1)

    def test_multitenant_reverse_equal_strength_keeps_global(self):
        """
        Test that when org-scoped record has equal strength to existing global,
        the global is NOT updated (comparison uses > not >=).
        """
        user = self._create_user(username="equal-strength-user")
        org = self._create_org(name="equal-org", slug="equal-org")
        modified_base = timezone.now()
        # Create existing global
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
        # Create org-scoped with IDENTICAL strength
        org_record = RegisteredUser.objects.create(
            user=user,
            organization=org,
            is_verified=True,
            method="email",
        )
        RegisteredUser.objects.filter(pk=org_record.pk).update(modified=modified_base)
        # Rollback: global should remain unchanged (equal strength, not greater)
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label="openwisp_radius"
        )
        existing_global.refresh_from_db()
        self.assertEqual(existing_global.organization, None)
        self.assertEqual(existing_global.method, "email")
        self.assertEqual(existing_global.modified, modified_base)
        self.assertEqual(existing_global.is_verified, True)
        # Org-scoped should be deleted
        self.assertEqual(
            RegisteredUser.objects.filter(
                user=user, organization__isnull=False
            ).exists(),
            False,
        )

    def test_multitenant_reverse_method_priority_ordering(self):
        """
        Test explicit method priority ordering: mobile_phone > email > empty.
        """
        user = self._create_user(username="method-priority-user")
        org1 = self._create_org(name="method-org-1", slug="method-org-1")
        org2 = self._create_org(name="method-org-2", slug="method-org-2")
        org3 = self._create_org(name="method-org-3", slug="method-org-3")
        modified_base = timezone.now()
        # All unverified, same timestamp - method should decide
        org_empty = RegisteredUser.objects.create(
            user=user,
            organization=org1,
            is_verified=False,
            method="",
        )
        RegisteredUser.objects.create(
            user=user,
            organization=org2,
            is_verified=False,
            method="email",
        )
        RegisteredUser.objects.create(
            user=user,
            organization=org3,
            is_verified=False,
            method="mobile_phone",
        )
        RegisteredUser.objects.update(modified=modified_base)
        # Rollback: mobile_phone should win (highest method priority)
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label="openwisp_radius"
        )
        global_record = RegisteredUser.objects.get(user=user, organization__isnull=True)
        self.assertEqual(global_record.method, "mobile_phone")

    def test_multitenant_reverse_full_cleanup(self):
        """
        Test that no org-scoped records remain after migration.
        """
        user1 = self._create_user(
            username="cleanup-user-1", email="cleanup1@example.com"
        )
        user2 = self._create_user(
            username="cleanup-user-2", email="cleanup2@example.com"
        )
        org1 = self._create_org(name="cleanup-org-1", slug="cleanup-org-1")
        org2 = self._create_org(name="cleanup-org-2", slug="cleanup-org-2")
        # Create multiple org-scoped records for multiple users
        for user, org in [(user1, org1), (user1, org2), (user2, org1)]:
            RegisteredUser.objects.create(
                user=user,
                organization=org,
                is_verified=False,
                method="email",
            )
        # Verify org-scoped records exist
        self.assertEqual(
            RegisteredUser.objects.filter(organization__isnull=False).exists(), True
        )
        # Rollback
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label="openwisp_radius"
        )
        # Verify NO org-scoped records remain
        self.assertEqual(
            RegisteredUser.objects.filter(organization__isnull=False).exists(), False
        )
