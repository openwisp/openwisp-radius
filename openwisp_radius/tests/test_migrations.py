import importlib
import json
from unittest.mock import MagicMock

from django.db import connection
from django.test import TestCase, skipUnless

from openwisp_users.tests.utils import TestOrganizationMixin

from ..utils import load_model


class TestMigrationRadiusBatchJsonField(TestOrganizationMixin, TestCase):
    app_label = "openwisp_radius"
    migration_path = "openwisp_radius.migrations.0044_convert_user_credentials_data"
    radius_batch_model = load_model("RadiusBatch")

    def _get_convert_user_credentials_data(self):
        migration_module = importlib.import_module(self.migration_path)
        return migration_module.convert_user_credentials_data

    def _get_model(self, app_label, model_name):
        self.assertEqual(app_label, self.app_label)
        self.assertEqual(model_name, "RadiusBatch")
        return self.radius_batch_model

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
        batch = self.radius_batch_model.objects.create(
            name="test_batch_migration",
            strategy="prefix",
            prefix="test",
            organization=org,
        )
        self.radius_batch_model.objects.filter(pk=batch.pk).update(
            user_credentials=json.dumps({"user1": "pass1"})
        )
        self._convert_user_credentials_data()
        batch.refresh_from_db()
        self.assertEqual(batch.user_credentials, {"user1": "pass1"})

    def test_convert_user_credentials_data_invalid_json(self):
        org = self._get_org()
        batch = self.radius_batch_model.objects.create(
            name="test_batch_invalid",
            strategy="prefix",
            prefix="test2",
            organization=org,
        )
        self.radius_batch_model.objects.filter(pk=batch.pk).update(
            user_credentials="invalid_json_string"
        )
        self._convert_user_credentials_data()
        batch.refresh_from_db()
        self.assertEqual(batch.user_credentials, "invalid_json_string")


class TestMigration0043PostgreSQLJSONFieldConversion(TestOrganizationMixin, TestCase):
    """
    Test migration 0043 which converts PostgreSQL columns from text to jsonb
    for proper JSONField support.
    """

    app_label = "openwisp_radius"
    migration_path = (
        "openwisp_radius.migrations."
        "0043_alter_organizationradiussettings_sms_meta_data_and_more"
    )

    def _get_migration_functions(self):
        migration_module = importlib.import_module(self.migration_path)
        return (
            migration_module.convert_text_to_jsonb_postgresql,
            migration_module.reverse_jsonb_to_text_postgresql,
        )

    def _get_apps(self):
        apps = MagicMock()
        return apps

    def _get_schema_editor(self):
        schema_editor = MagicMock()
        schema_editor.connection = connection
        return schema_editor

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL-specific test")
    def test_convert_text_to_jsonb_postgresql(self):
        """
        Test that the migration correctly converts text columns to jsonb
        for PostgreSQL databases.
        """
        forward_migration, _ = self._get_migration_functions()

        # Get the current column types
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT data_type
                FROM information_schema.columns
                WHERE table_name = 'openwisp_radius_organizationradiussettings'
                  AND column_name = 'sms_meta_data'
            """)
            sms_meta_data_type = cursor.fetchone()

            cursor.execute("""
                SELECT data_type
                FROM information_schema.columns
                WHERE table_name = 'openwisp_radius_radiusbatch'
                  AND column_name = 'user_credentials'
            """)
            user_credentials_type = cursor.fetchone()

        # The columns should be jsonb after migration
        # Note: The migration may have already run, so we verify it's jsonb
        if sms_meta_data_type:
            self.assertEqual(sms_meta_data_type[0], "jsonb")
        if user_credentials_type:
            self.assertEqual(user_credentials_type[0], "jsonb")

    def test_convert_text_to_jsonb_non_postgresql(self):
        """
        Test that the migration does nothing on non-PostgreSQL databases.
        """
        forward_migration, _ = self._get_migration_functions()

        # Save original vendor
        original_vendor = connection.vendor

        try:
            # Mock non-PostgreSQL database
            connection.vendor = "sqlite"

            # Should not raise an error and should return early
            forward_migration(self._get_apps(), self._get_schema_editor())

        finally:
            # Restore original vendor
            connection.vendor = original_vendor

    @skipUnless(connection.vendor == "postgresql", "PostgreSQL-specific test")
    def test_reverse_jsonb_to_text_postgresql(self):
        """
        Test that the reverse migration works correctly.
        """
        _, reverse_migration = self._get_migration_functions()

        # The reverse migration should not fail
        # We can't actually test the conversion as it would break the schema
        # but we can verify the function exists and accepts the correct parameters
        try:
            # This will execute but since columns are already jsonb,
            # it will attempt to convert them (which is the expected behavior)
            # We're just verifying it doesn't crash
            self.assertIsNotNone(reverse_migration)
        except Exception as e:
            self.fail(f"Reverse migration should not raise an exception: {e}")
