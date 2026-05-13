from datetime import timedelta

from django.apps.registry import apps
from django.db import connection
from django.utils import timezone
from freezegun import freeze_time

from ..migrations import migrate_registered_users_multitenant_reverse
from ..utils import load_model
from .mixins import BaseTestCase

RegisteredUser = load_model("RegisteredUser")


class TestMigrations(BaseTestCase):
    app_label = "openwisp_radius"

    def test_registered_user_organization_column_is_not_nullable(self):
        registered_user_model = load_model("RegisteredUser")
        table_name = registered_user_model._meta.db_table
        column_name = registered_user_model._meta.get_field("organization").column
        with connection.cursor() as cursor:
            columns = connection.introspection.get_table_description(
                cursor,
                table_name,
            )
        column = next(
            (col for col in columns if col.name == column_name),
            None,
        )
        self.assertIsNotNone(
            column,
            f"Column '{column_name}' not found in '{table_name}'",
        )
        self.assertFalse(
            column.null_ok,
            f"Column '{table_name}.{column_name}' must be NOT NULL at DB level",
        )

    def test_multitenant_reverse_keeps_record_with_stronger_method(self):
        """
        Test that a stronger verification method wins when verification
        status is equal.
        """
        user = self._create_user(
            username="rollback-stronger",
            email="rollback-stronger@example.com",
        )
        org1 = self.default_org
        org2 = self._create_org(name="rollback-org-2", slug="rollback-org-2")
        modified_base = timezone.now()
        with freeze_time(modified_base):
            RegisteredUser.objects.create(
                user=user,
                organization=org1,
                is_verified=True,
                method="email",
            )
            stronger_record = RegisteredUser.objects.create(
                user=user,
                organization=org2,
                is_verified=True,
                method="mobile_phone",
            )

        migrate_registered_users_multitenant_reverse(
            apps, None, app_label=self.app_label
        )
        surviving_record = RegisteredUser.objects.get(user=user)
        self.assertEqual(surviving_record.pk, stronger_record.pk)
        self.assertEqual(surviving_record.organization.slug, "rollback-org-2")
        self.assertEqual(surviving_record.method, "mobile_phone")
        self.assertEqual(
            RegisteredUser.objects.filter(user=user).count(),
            1,
        )

    def test_multitenant_reverse_keeps_existing_strongest_record(self):
        """
        Test that the already-strongest record remains after rollback.
        """
        user = self._create_user(
            username="rollback-strongest-wins",
            email="rollback-strongest-wins@example.com",
        )
        org1 = self._create_org(
            name="rollback-org-3",
            slug="rollback-org-3",
        )
        org2 = self._create_org(
            name="rollback-org-4",
            slug="rollback-org-4",
        )
        modified_base = timezone.now()
        with freeze_time(modified_base):
            strongest_record = RegisteredUser.objects.create(
                user=user,
                organization=org1,
                is_verified=True,
                method="mobile_phone",
            )
            RegisteredUser.objects.create(
                user=user,
                organization=org2,
                is_verified=True,
                method="social_login",
            )

        migrate_registered_users_multitenant_reverse(
            apps, None, app_label=self.app_label
        )
        surviving_record = RegisteredUser.objects.get(user=user)
        self.assertEqual(surviving_record.pk, strongest_record.pk)
        self.assertEqual(surviving_record.organization.slug, "rollback-org-3")
        self.assertEqual(surviving_record.method, "mobile_phone")
        self.assertEqual(
            RegisteredUser.objects.filter(user=user).count(),
            1,
        )

    def test_multitenant_reverse_uses_modified_timestamp_as_tiebreaker(self):
        """
        Test that the most recently modified record wins when strength
        is otherwise equal.
        """
        user = self._create_user(
            username="timestamp-wins-user",
            email="timestamp-wins-user@example.com",
        )
        org1 = self._create_org(
            name="timestamp-org-1",
            slug="timestamp-org-1",
        )
        org2 = self._create_org(
            name="timestamp-org-2",
            slug="timestamp-org-2",
        )
        modified_base = timezone.now()
        with freeze_time(modified_base):
            RegisteredUser.objects.create(
                user=user,
                organization=org1,
                is_verified=True,
                method="email",
            )
        newer_record = RegisteredUser.objects.create(
            user=user,
            organization=org2,
            is_verified=True,
            method="email",
        )
        RegisteredUser.objects.filter(pk=newer_record.pk).update(
            modified=modified_base + timedelta(seconds=1)
        )

        migrate_registered_users_multitenant_reverse(
            apps, None, app_label=self.app_label
        )
        surviving_record = RegisteredUser.objects.get(user=user)
        self.assertEqual(surviving_record.pk, newer_record.pk)
        self.assertEqual(surviving_record.organization.slug, "timestamp-org-2")
        self.assertEqual(surviving_record.method, "email")
        self.assertEqual(
            RegisteredUser.objects.filter(user=user).count(),
            1,
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
        with freeze_time(modified_base):
            RegisteredUser.objects.create(
                user=user,
                organization=org1,
                is_verified=False,
                method="mobile_phone",
            )
            org_weak_method = RegisteredUser.objects.create(
                user=user,
                organization=org2,
                is_verified=True,
                method="email",
            )
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label=self.app_label
        )
        surviving_record = RegisteredUser.objects.get(user=user)
        self.assertEqual(surviving_record.pk, org_weak_method.pk)
        self.assertEqual(surviving_record.is_verified, True)
        self.assertEqual(surviving_record.method, "email")
        self.assertEqual(RegisteredUser.objects.filter(user=user).count(), 1)

    def test_multitenant_reverse_equal_strength_keeps_first_record(self):
        """
        Test that equal-strength records are reduced to one remaining row.
        """
        user = self._create_user(username="equal-strength-user")
        org1 = self._create_org(name="equal-org-1", slug="equal-org-1")
        org2 = self._create_org(name="equal-org-2", slug="equal-org-2")
        modified_base = timezone.now()
        with freeze_time(modified_base):
            first_record = RegisteredUser.objects.create(
                user=user,
                organization=org1,
                is_verified=True,
                method="email",
            )

            RegisteredUser.objects.create(
                user=user,
                organization=org2,
                is_verified=True,
                method="email",
            )
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label=self.app_label
        )
        self.assertEqual(
            RegisteredUser.objects.filter(user=user).count(),
            1,
        )
        surviving_record = RegisteredUser.objects.get(user=user)
        self.assertEqual(surviving_record.is_verified, True)
        self.assertEqual(surviving_record.method, "email")
        self.assertEqual(surviving_record.pk, first_record.pk)

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
        with freeze_time(modified_base):
            RegisteredUser.objects.create(
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
        # Rollback: mobile_phone should win (highest method priority)
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label=self.app_label
        )
        surviving_record = RegisteredUser.objects.get(user=user)
        self.assertEqual(surviving_record.organization, org3)
        self.assertEqual(surviving_record.method, "mobile_phone")
        self.assertEqual(RegisteredUser.objects.filter(user=user).count(), 1)

    def test_multitenant_reverse_pending_verification_method_ignored(
        self,
    ):
        user = self._create_user(
            username="pending-vs-strong",
            email="pending-vs-strong@example.com",
        )
        org1 = self._create_org(
            name="pending-org-1",
            slug="pending-org-1",
        )
        org2 = self._create_org(
            name="pending-org-2",
            slug="pending-org-2",
        )
        modified_base = timezone.now()
        with freeze_time(modified_base):
            RegisteredUser.objects.create(
                user=user,
                organization=org1,
                is_verified=False,
                method="pending_verification",
            )
            strong_record = RegisteredUser.objects.create(
                user=user,
                organization=org2,
                is_verified=False,
                method="mobile_phone",
            )
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label=self.app_label
        )
        surviving_record = RegisteredUser.objects.get(user=user)
        self.assertEqual(surviving_record.pk, strong_record.pk)
        self.assertEqual(surviving_record.method, "mobile_phone")
        self.assertEqual(RegisteredUser.objects.filter(user=user).count(), 1)

    def test_multitenant_reverse_full_cleanup(self):
        """
        Test that duplicate org-scoped records are reduced to one per user.
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
        self.assertEqual(
            RegisteredUser.objects.filter(user=user1).count(),
            2,
        )
        migrate_registered_users_multitenant_reverse(
            apps, None, app_label=self.app_label
        )
        self.assertEqual(
            RegisteredUser.objects.filter(user=user1).count(),
            1,
        )
        self.assertEqual(
            RegisteredUser.objects.filter(user=user2).count(),
            1,
        )
