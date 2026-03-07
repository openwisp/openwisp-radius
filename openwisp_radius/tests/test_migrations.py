import importlib
import json
from unittest.mock import MagicMock

from django.db import connection
from django.test import TestCase

from openwisp_radius.models import RadiusBatch

migration_module = importlib.import_module(
    "openwisp_radius.migrations.0044_convert_user_credentials_data"
)
convert_user_credentials_data = migration_module.convert_user_credentials_data


class Test0044Migration(TestCase):
    def test_convert_user_credentials_data(self):
        batch = RadiusBatch.objects.create(
            name="test_batch_migration", strategy="prefix", prefix="test"
        )
        RadiusBatch.objects.filter(pk=batch.pk).update(
            user_credentials=json.dumps({"user1": "pass1"})
        )

        apps = MagicMock()
        apps.get_model.return_value = RadiusBatch

        schema_editor = MagicMock()
        schema_editor.connection = connection

        convert_user_credentials_data(apps, schema_editor)

        batch.refresh_from_db()
        self.assertEqual(batch.user_credentials, {"user1": "pass1"})

    def test_convert_user_credentials_data_invalid_json(self):
        batch = RadiusBatch.objects.create(
            name="test_batch_invalid", strategy="prefix", prefix="test2"
        )
        RadiusBatch.objects.filter(pk=batch.pk).update(
            user_credentials="invalid_json_string"
        )

        apps = MagicMock()
        apps.get_model.return_value = RadiusBatch

        schema_editor = MagicMock()
        schema_editor.connection = connection

        convert_user_credentials_data(apps, schema_editor)

        batch.refresh_from_db()
        self.assertEqual(batch.user_credentials, "invalid_json_string")
