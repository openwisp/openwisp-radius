from django.db import migrations
from openwisp_radius.migrations import update_obj_pk


class Migration(migrations.Migration):

    dependencies = [
        ('sample_radius', '0003_alter_radiusmodels_pk'),
    ]

    operations = [
        migrations.RunPython(update_obj_pk, reverse_code=migrations.RunPython.noop),
    ]
