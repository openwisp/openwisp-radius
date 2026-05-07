from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("openwisp_radius", "0044_registered_user_multitenant_data"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="registereduser",
            constraint=models.UniqueConstraint(
                fields=["user", "organization"],
                name="unique_registered_user_per_org",
                violation_error_message=(
                    "A user cannot have more than one registration record in the same"
                    " organization."
                ),
            ),
        ),
    ]
