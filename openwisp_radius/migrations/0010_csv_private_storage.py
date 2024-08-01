# Generated by Django 3.0.7 on 2020-06-18 15:37

from urllib.parse import urljoin

import private_storage.fields
import private_storage.storage.files
from django.conf import settings
from django.db import migrations

import openwisp_radius.base.models

from .. import settings as app_settings


class Migration(migrations.Migration):
    dependencies = [
        ('openwisp_radius', '0009_radbatch_user_credentials_field'),
    ]

    operations = [
        migrations.AlterField(
            model_name='radiusbatch',
            name='csvfile',
            field=private_storage.fields.PrivateFileField(
                blank=True,
                help_text='The csv file containing the user details to be uploaded',
                null=True,
                storage=private_storage.storage.files.PrivateFileSystemStorage(
                    base_url=urljoin(
                        app_settings.RADIUS_API_BASEURL, app_settings.CSV_URL_PATH
                    ),
                    location=settings.PRIVATE_STORAGE_ROOT,
                ),
                upload_to=openwisp_radius.base.models._get_csv_file_location,
                verbose_name='CSV',
            ),
        ),
    ]
