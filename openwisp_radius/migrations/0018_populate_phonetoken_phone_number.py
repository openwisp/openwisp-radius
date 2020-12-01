from django.db import migrations

from . import populate_phonetoken_phone_number


class Migration(migrations.Migration):

    dependencies = [
        ('openwisp_radius', '0017_phonetoken_phone_number'),
    ]

    operations = [
        migrations.RunPython(
            populate_phonetoken_phone_number, reverse_code=migrations.RunPython.noop
        ),
    ]
