from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("openwisp_radius", "0044_registered_user_multitenant_data"),
    ]

    operations = [
        migrations.AlterField(
            model_name="registereduser",
            name="organization",
            field=models.ForeignKey(
                help_text="Organization associated with this registered user entry.",
                on_delete=models.deletion.CASCADE,
                related_name="registered_users",
                to="openwisp_users.organization",
                verbose_name="organization",
            ),
        ),
    ]
