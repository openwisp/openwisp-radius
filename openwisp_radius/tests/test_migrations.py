import importlib
import json
import uuid
from datetime import timedelta
from unittest.mock import MagicMock

import swapper
from django.apps.registry import apps
from django.db import connection
from django.test import TestCase
from django.utils import timezone
from freezegun import freeze_time

from openwisp_users.tests.utils import TestOrganizationMixin
from openwisp_utils.tests import capture_any_output

from ..migrations import (
    _filter_valid_organization_memberships,
    _filter_valid_registered_users,
    _get_first_valid_membership_organization_id,
    migrate_registered_users_multitenant_reverse,
)
from ..utils import load_model
from .mixins import BaseTestCase

RegisteredUser = load_model("RegisteredUser")
RadiusBatch = load_model("RadiusBatch")
OrganizationUser = swapper.load_model("openwisp_users", "OrganizationUser")


class TestMigrationRegisteredUserMultitenancy(BaseTestCase):
    def _get_app_label(self):
        return RegisteredUser._meta.app_label

    def _assert_column_not_nullable(self, model_name, field_name):
        model = load_model(model_name)
        table_name = model._meta.db_table
        column_name = model._meta.get_field(field_name).column
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

    def test_registered_user_organization_column_is_not_nullable(self):
        self._assert_column_not_nullable("RegisteredUser", "organization")

    def test_phone_token_organization_column_is_not_nullable(self):
        self._assert_column_not_nullable("PhoneToken", "organization")

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
            apps, None, app_label=self._get_app_label()
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
            apps, None, app_label=self._get_app_label()
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
            apps, None, app_label=self._get_app_label()
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
            apps, None, app_label=self._get_app_label()
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
            apps, None, app_label=self._get_app_label()
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
            apps, None, app_label=self._get_app_label()
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
            apps, None, app_label=self._get_app_label()
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
            apps, None, app_label=self._get_app_label()
        )
        self.assertEqual(
            RegisteredUser.objects.filter(user=user1).count(),
            1,
        )
        self.assertEqual(
            RegisteredUser.objects.filter(user=user2).count(),
            1,
        )

    def test_registered_user_filter_skips_rows_with_missing_user(self):
        valid_suffix = uuid.uuid4().hex[:8]
        orphan_suffix = uuid.uuid4().hex[:8]
        valid_user = self._create_user(
            username=f"valid-user-{valid_suffix}",
            email=f"valid-user-{valid_suffix}@example.com",
        )
        orphan_user = self._create_user(
            username=f"orphan-user-{orphan_suffix}",
            email=f"orphan-user-{orphan_suffix}@example.com",
        )
        valid_registered_user = RegisteredUser.objects.create(
            user=valid_user,
            organization=self.default_org,
            method="email",
            is_verified=True,
        )
        orphan_registered_user = RegisteredUser.objects.create(
            user=orphan_user,
            organization=self.default_org,
            method="mobile_phone",
            is_verified=True,
        )
        # Simulate a dangling user reference by setting the user_id to
        #  a non-existent value
        with connection.constraint_checks_disabled():
            missing_user_id = uuid.uuid4()
            registered_user_pk = RegisteredUser._meta.pk.get_db_prep_value(
                orphan_registered_user.pk,
                connection,
            )
            missing_user_db_value = RegisteredUser._meta.get_field(
                "user"
            ).target_field.get_db_prep_value(
                missing_user_id,
                connection,
            )
            with connection.cursor() as cursor:
                # We have to use raw SQL here because the ORM would not allow
                # us to set a non-existent user_id
                cursor.execute(
                    f'UPDATE "{RegisteredUser._meta.db_table}" '
                    f'SET "{RegisteredUser._meta.get_field("user").column}" = %s '
                    f'WHERE "{RegisteredUser._meta.pk.column}" = %s',
                    [missing_user_db_value, registered_user_pk],
                )
            self.assertEqual(
                RegisteredUser.objects.get(pk=orphan_registered_user.pk).user_id,
                missing_user_id,
            )

            filtered_ids = list(
                _filter_valid_registered_users(
                    RegisteredUser.objects.order_by("pk"),
                    apps,
                ).values_list("pk", flat=True)
            )
            self.assertEqual(filtered_ids, [valid_registered_user.pk])
            RegisteredUser.objects.filter(pk=orphan_registered_user.pk).delete()


class TestPhoneTokenOrganizationPopulateResolution(BaseTestCase):
    def _delete_org_user_row(self, org_user):
        org_user_pk = OrganizationUser._meta.pk.get_db_prep_value(
            org_user.pk,
            connection,
        )
        with connection.cursor() as cursor:
            # We have to use raw SQL here because the ORM would not allow
            # us to delete the row since it would violate foreign key constraints
            cursor.execute(
                f'DELETE FROM "{OrganizationUser._meta.db_table}" '
                f'WHERE "{OrganizationUser._meta.pk.column}" = %s',
                [org_user_pk],
            )

    def _set_org_user_created(self, org_user, created):
        OrganizationUser.objects.filter(pk=org_user.pk).update(created=created)
        org_user.refresh_from_db(fields=["created"])
        return org_user

    def _set_org_user_user_id(self, org_user, user_id):
        org_user_pk = OrganizationUser._meta.pk.get_db_prep_value(
            org_user.pk,
            connection,
        )
        user_db_value = OrganizationUser._meta.get_field(
            "user"
        ).target_field.get_db_prep_value(
            user_id,
            connection,
        )
        with connection.cursor() as cursor:
            cursor.execute(
                f'UPDATE "{OrganizationUser._meta.db_table}" '
                f'SET "{OrganizationUser._meta.get_field("user").column}" = %s '
                f'WHERE "{OrganizationUser._meta.pk.column}" = %s',
                [user_db_value, org_user_pk],
            )

    def _set_org_user_organization_id(self, org_user, organization_id):
        org_user_pk = OrganizationUser._meta.pk.get_db_prep_value(
            org_user.pk,
            connection,
        )
        organization_db_value = OrganizationUser._meta.get_field(
            "organization"
        ).target_field.get_db_prep_value(
            organization_id,
            connection,
        )
        with connection.cursor() as cursor:
            cursor.execute(
                f'UPDATE "{OrganizationUser._meta.db_table}" '
                f'SET "{OrganizationUser._meta.get_field("organization").column}" = %s '
                f'WHERE "{OrganizationUser._meta.pk.column}" = %s',
                [organization_db_value, org_user_pk],
            )

    def test_filter_memberships_skips_rows_with_missing_organization(self):
        user = self._create_user(username="membership-filter-user")
        org1 = self.default_org
        org2 = self._create_org(
            name="membership-filter-org2", slug="membership-filter-org2"
        )
        invalid_membership = OrganizationUser.objects.create(
            user=user, organization=org1
        )
        valid_membership = OrganizationUser.objects.create(user=user, organization=org2)

        with connection.constraint_checks_disabled():
            self._set_org_user_organization_id(invalid_membership, uuid.uuid4())
            organization_ids = list(
                _filter_valid_organization_memberships(
                    OrganizationUser.objects.filter(user=user).order_by(
                        "created", "pk"
                    ),
                    apps,
                ).values_list("organization_id", flat=True)
            )
            self.assertEqual(organization_ids, [valid_membership.organization_id])
            self._delete_org_user_row(invalid_membership)

    def test_filter_memberships_skips_rows_with_missing_user(self):
        valid_suffix = uuid.uuid4().hex[:8]
        broken_suffix = uuid.uuid4().hex[:8]
        valid_user = self._create_user(
            username=f"membership-filter-valid-user-{valid_suffix}",
            email=f"membership-filter-valid-user-{valid_suffix}@example.com",
        )
        broken_user = self._create_user(
            username=f"membership-filter-broken-user-{broken_suffix}",
            email=f"membership-filter-broken-user-{broken_suffix}@example.com",
        )
        org1 = self.default_org
        org2 = self._create_org(
            name="membership-filter-user-org2", slug="membership-filter-user-org2"
        )
        invalid_membership = OrganizationUser.objects.create(
            user=broken_user, organization=org1
        )
        valid_membership = OrganizationUser.objects.create(
            user=valid_user, organization=org2
        )

        with connection.constraint_checks_disabled():
            self._set_org_user_user_id(invalid_membership, uuid.uuid4())
            membership_ids = list(
                _filter_valid_organization_memberships(
                    OrganizationUser.objects.filter(
                        pk__in=[invalid_membership.pk, valid_membership.pk]
                    ).order_by("created", "pk"),
                    apps,
                ).values_list("pk", flat=True)
            )
            self.assertEqual(membership_ids, [valid_membership.pk])
            self._delete_org_user_row(invalid_membership)

    def test_get_first_membership_returns_earliest_membership(self):
        user = self._create_user(username="phone-membership-user")
        org1 = self.default_org
        org2 = self._create_org(
            name="phone-membership-org2", slug="phone-membership-org2"
        )
        org1_user = OrganizationUser.objects.create(user=user, organization=org1)
        org2_user = OrganizationUser.objects.create(user=user, organization=org2)
        base_time = timezone.now()
        self._set_org_user_created(org1_user, base_time + timedelta(days=1))
        self._set_org_user_created(org2_user, base_time)
        organization_id = _get_first_valid_membership_organization_id(
            user.pk,
            OrganizationUser,
            apps,
        )
        self.assertEqual(organization_id, org2.pk)

    def test_get_first_membership_skips_missing_organization(self):
        user = self._create_user(username="phone-membership-dangling-user")
        org1 = self.default_org
        org2 = self._create_org(
            name="phone-membership-valid-org", slug="phone-membership-valid-org"
        )
        invalid_membership = OrganizationUser.objects.create(
            user=user, organization=org1
        )
        valid_membership = OrganizationUser.objects.create(user=user, organization=org2)
        base_time = timezone.now()
        self._set_org_user_created(invalid_membership, base_time)
        self._set_org_user_created(valid_membership, base_time + timedelta(days=1))

        with connection.constraint_checks_disabled():
            self._set_org_user_organization_id(invalid_membership, uuid.uuid4())
            organization_id = _get_first_valid_membership_organization_id(
                user.pk,
                OrganizationUser,
                apps,
            )
            self.assertEqual(organization_id, valid_membership.organization_id)
            self._delete_org_user_row(invalid_membership)

    def test_get_first_membership_returns_none_for_missing_user_membership(self):
        user = self._create_user(username="phone-membership-missing-user")
        membership = OrganizationUser.objects.create(
            user=user,
            organization=self.default_org,
        )

        with connection.constraint_checks_disabled():
            missing_user_id = uuid.uuid4()
            self._set_org_user_user_id(membership, missing_user_id)
            organization_id = _get_first_valid_membership_organization_id(
                missing_user_id,
                OrganizationUser,
                apps,
            )
            self.assertEqual(organization_id, None)
            self._delete_org_user_row(membership)

    def test_get_first_membership_returns_none_without_membership(self):
        user = self._create_user(username="phone-unresolved-user")
        organization_id = _get_first_valid_membership_organization_id(
            user.pk,
            OrganizationUser,
            apps,
        )
        self.assertEqual(organization_id, None)


class TestMigrationRadiusBatchJsonField(TestOrganizationMixin, TestCase):
    migration_path = "openwisp_radius.migrations.0044_convert_user_credentials_data"

    def _get_app_label(self):
        return RadiusBatch._meta.app_label

    def _get_convert_user_credentials_data(self):
        migration_module = importlib.import_module(self.migration_path)
        return migration_module.convert_user_credentials_data

    def _get_model(self, app_label, model_name):
        self.assertEqual(app_label, self._get_app_label())
        self.assertEqual(model_name, "RadiusBatch")
        return RadiusBatch

    def _get_apps(self):
        apps = MagicMock()
        apps.get_model.side_effect = self._get_model
        return apps

    def _get_schema_editor(self):
        schema_editor = MagicMock()
        schema_editor.connection = connection
        return schema_editor

    def _convert_user_credentials_data(self):
        convert_user_credentials_data = self._get_convert_user_credentials_data()
        convert_user_credentials_data(self._get_apps(), self._get_schema_editor())

    def test_convert_user_credentials_data(self):
        org = self._get_org()
        batch = RadiusBatch.objects.create(
            name="test_batch_migration",
            strategy="prefix",
            prefix="test",
            organization=org,
        )
        RadiusBatch.objects.filter(pk=batch.pk).update(
            user_credentials=json.dumps({"user1": "pass1"})
        )
        self._convert_user_credentials_data()
        batch.refresh_from_db()
        self.assertEqual(batch.user_credentials, {"user1": "pass1"})

    @capture_any_output()
    def test_convert_user_credentials_data_invalid_json(self):
        org = self._get_org()
        batch = RadiusBatch.objects.create(
            name="test_batch_invalid",
            strategy="prefix",
            prefix="test2",
            organization=org,
        )
        RadiusBatch.objects.filter(pk=batch.pk).update(
            user_credentials="invalid_json_string"
        )
        self._convert_user_credentials_data()
        batch.refresh_from_db()
        self.assertEqual(batch.user_credentials, "invalid_json_string")


class TestMigrationRadiusBatchExpirationDateCopy(BaseTestCase):
    migration_path = "openwisp_radius.migrations.0048_copy_batch_expiration_to_user"

    def _get_copy_batch_expiration_to_user(self):
        migration_module = importlib.import_module(self.migration_path)
        return migration_module.copy_batch_expiration_to_user

    def _get_model(self, app_label, model_name):
        self.assertEqual(model_name, "RadiusBatch")
        return RadiusBatch

    def _get_apps(self):
        apps = MagicMock()
        apps.get_model.side_effect = self._get_model
        return apps

    def _copy_batch_expiration_to_user(self):
        copy_batch_expiration_to_user = self._get_copy_batch_expiration_to_user()
        copy_batch_expiration_to_user(self._get_apps(), MagicMock())

    def test_copy_batch_expiration_to_user(self):
        copied_expiration_date = timezone.now().date() + timedelta(days=7)
        batch_with_expiration = self._create_radius_batch(
            name="batch-with-expiration",
            strategy="prefix",
            prefix="batchcopy1",
            expiration_date=copied_expiration_date,
        )
        batch_without_expiration = self._create_radius_batch(
            name="batch-without-expiration",
            strategy="prefix",
            prefix="batchcopy2",
        )
        copied_user = self._create_user(username="batch-copy-user")
        untouched_user = self._create_user(
            username="batch-copy-user-no-exp", email="batch-copy-user-no-exp@text.com"
        )
        batch_with_expiration.users.add(copied_user)
        batch_without_expiration.users.add(untouched_user)
        self._copy_batch_expiration_to_user()
        copied_user.refresh_from_db()
        untouched_user.refresh_from_db()
        self.assertEqual(copied_user.expiration_date, copied_expiration_date)
        self.assertEqual(untouched_user.expiration_date, None)

    def test_copy_batch_expiration_to_user_keeps_existing_user_expiration(self):
        original_expiration_date = timezone.now().date() + timedelta(days=30)
        batch_expiration_date = timezone.now().date() + timedelta(days=7)
        batch = self._create_radius_batch(
            name="batch-preserve-expiration",
            strategy="prefix",
            prefix="batchcopy3",
            expiration_date=batch_expiration_date,
        )
        user = self._create_user(
            username="batch-copy-preserve-user",
            expiration_date=original_expiration_date,
        )
        batch.users.add(user)
        self._copy_batch_expiration_to_user()
        user.refresh_from_db()
        self.assertEqual(user.expiration_date, original_expiration_date)

    def test_copy_batch_expiration_to_user_prefers_latest_batch(self):
        older_expiration_date = timezone.now().date() + timedelta(days=7)
        newer_expiration_date = timezone.now().date() + timedelta(days=14)
        older_batch = self._create_radius_batch(
            name="batch-older-expiration",
            strategy="prefix",
            prefix="batchcopy4",
            expiration_date=older_expiration_date,
        )
        newer_batch = self._create_radius_batch(
            name="batch-newer-expiration",
            strategy="prefix",
            prefix="batchcopy5",
            expiration_date=newer_expiration_date,
        )
        user = self._create_user(username="batch-copy-latest-user")

        RadiusBatch.objects.filter(pk=older_batch.pk).update(
            created=timezone.now() - timedelta(days=1)
        )
        RadiusBatch.objects.filter(pk=newer_batch.pk).update(created=timezone.now())
        older_batch.users.add(user)
        newer_batch.users.add(user)
        self._copy_batch_expiration_to_user()
        user.refresh_from_db()
        self.assertEqual(user.expiration_date, newer_expiration_date)
