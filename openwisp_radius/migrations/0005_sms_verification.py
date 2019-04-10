import uuid

import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
from django.conf import settings
from django.db import migrations, models

import openwisp_radius.utils

from .. import settings as app_settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('openwisp_radius', '0004_default_permissions'),
        ('openwisp_users', '0005_user_phone_number'),
    ]

    operations = [
        migrations.AddField(
            model_name='organizationradiussettings',
            name='sms_verification',
            field=models.BooleanField(
                default=app_settings.SMS_DEFAULT_VERIFICATION,
                help_text=('whether users who sign up should be required to '
                           'verify their mobile phone number via SMS')),
        ),
        migrations.CreateModel(
            name='PhoneToken',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created', model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, editable=False, verbose_name='created')),
                ('modified', model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, editable=False, verbose_name='modified')),
                ('valid_until', models.DateTimeField(default=openwisp_radius.utils.get_sms_default_valid_until)),
                ('attempts', models.PositiveIntegerField(default=0)),
                ('verified', models.BooleanField(default=False)),
                ('token', models.CharField(default=openwisp_radius.utils.generate_sms_token, editable=False, max_length=8)),
                ('ip', models.GenericIPAddressField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
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
