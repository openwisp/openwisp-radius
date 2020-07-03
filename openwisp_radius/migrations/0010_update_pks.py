from django.db import migrations

from . import update_obj_pk


class Migration(migrations.Migration):

    dependencies = [
        ('openwisp_radius', '0009_alter_radiusmodels_pk'),
    ]

    operations = [
        migrations.RunPython(update_obj_pk, reverse_code=migrations.RunPython.noop),
    ]
