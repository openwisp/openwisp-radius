# Generated by Django 3.1.13 on 2022-02-09 17:54

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('openwisp_radius', '0026_login_status_url_org_settings'),
    ]

    operations = [
        migrations.AddField(
            model_name='organizationradiussettings',
            name='password_reset_url',
            field=models.URLField(
                blank=True,
                help_text='Enter the URL where users can reset their password',
                null=True,
                verbose_name='Password reset URL',
            ),
        ),
    ]
