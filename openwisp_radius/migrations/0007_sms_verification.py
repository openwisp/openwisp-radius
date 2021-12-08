import uuid

import django.db.models.deletion
import django.utils.timezone
import jsonfield.fields
import model_utils.fields
import phonenumber_field.modelfields
from django.conf import settings
from django.db import migrations, models

import openwisp_radius.utils

from .. import settings as app_settings


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('openwisp_radius', '0006_add_radactt_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='organizationradiussettings',
            name='sms_verification',
            field=models.BooleanField(
                default=app_settings.SMS_VERIFICATION_ENABLED,
                help_text=(
                    'whether users who sign up should be required to '
                    'verify their mobile phone number via SMS'
                ),
            ),
        ),
        migrations.AddField(
            model_name='organizationradiussettings',
            name='sms_phone_number',
            field=phonenumber_field.modelfields.PhoneNumberField(
                blank=True,
                max_length=128,
                null=True,
                region=None,
                help_text=(
                    'phone number used as sender for SMS sent by this organization'
                ),
            ),
        ),
        migrations.AddField(
            model_name='organizationradiussettings',
            name='sms_meta_data',
            field=jsonfield.fields.JSONField(
                blank=True,
                help_text=(
                    'Additional configuration for SMS backend '
                    'in JSON format (optional)'
                ),
                null=True,
            ),
        ),
        migrations.CreateModel(
            name='PhoneToken',
            fields=[
                (
                    'id',
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    'created',
                    model_utils.fields.AutoCreatedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='created',
                    ),
                ),
                (
                    'modified',
                    model_utils.fields.AutoLastModifiedField(
                        default=django.utils.timezone.now,
                        editable=False,
                        verbose_name='modified',
                    ),
                ),
                (
                    'valid_until',
                    models.DateTimeField(
                        default=openwisp_radius.utils.get_sms_default_valid_until
                    ),
                ),
                ('attempts', models.PositiveIntegerField(default=0)),
                ('verified', models.BooleanField(default=False)),
                (
                    'token',
                    models.CharField(
                        default=openwisp_radius.utils.generate_sms_token,
                        editable=False,
                        max_length=8,
                    ),
                ),
                ('ip', models.GenericIPAddressField()),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'verbose_name': 'Phone verification token',
                'ordering': ('-created',),
                'verbose_name_plural': 'Phone verification tokens',
            },
        ),
        migrations.AlterIndexTogether(
            name='phonetoken',
            index_together={('user', 'created', 'ip'), ('user', 'created')},
        ),
    ]
