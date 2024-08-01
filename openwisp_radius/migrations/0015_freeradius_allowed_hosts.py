# Generated by Django 3.0.7 on 2020-07-12 15:46

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('openwisp_radius', '0014_radiustoken_freeradius_auth'),
    ]

    operations = [
        migrations.AddField(
            model_name='organizationradiussettings',
            name='freeradius_allowed_hosts',
            field=models.TextField(
                blank=True,
                help_text=(
                    'Comma separated list of IP addresses '
                    'allowed to access freeradius API'
                ),
                null=True,
            ),
        ),
    ]
