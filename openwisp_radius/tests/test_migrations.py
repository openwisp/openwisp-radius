import importlib
import json
from unittest.mock import MagicMock

from django.db import connection
from django.test import TestCase

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
