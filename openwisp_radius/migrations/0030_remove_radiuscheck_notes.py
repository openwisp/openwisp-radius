# Generated by Django 3.2.12 on 2022-04-11 18:17

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("openwisp_radius", "0029_remove_check_customizations"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="radiuscheck",
            name="notes",
        ),
    ]
