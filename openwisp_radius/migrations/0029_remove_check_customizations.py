# Generated by Django 3.1.13 on 2021-12-22 08:46

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        (
            "openwisp_radius",
            "0028_organizationradiussettings_saml_social_registration_enabled",
        ),
    ]

    operations = [
        migrations.RemoveField(
            model_name="radiuscheck",
            name="is_active",
        ),
        migrations.RemoveField(
            model_name="radiuscheck",
            name="valid_until",
        ),
        migrations.AlterField(
            model_name="radiuscheck",
            name="attribute",
            field=models.CharField(max_length=64, verbose_name="attribute"),
        ),
    ]
