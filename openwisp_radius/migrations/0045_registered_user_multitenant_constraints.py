import swapper
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        swapper.dependency("openwisp_users", "Organization"),
        ("openwisp_radius", "0044_registered_user_multitenant_data"),
    ]

    operations = [
        migrations.AlterField(
            model_name="phonetoken",
            name="organization",
            field=models.ForeignKey(
                on_delete=models.deletion.CASCADE,
                to=swapper.get_model_name("openwisp_users", "Organization"),
                verbose_name="organization",
            ),
        ),
        migrations.AlterField(
            model_name="registereduser",
            name="organization",
            field=models.ForeignKey(
                on_delete=models.deletion.CASCADE,
                to=swapper.get_model_name("openwisp_users", "Organization"),
                verbose_name="organization",
            ),
        ),
    ]
