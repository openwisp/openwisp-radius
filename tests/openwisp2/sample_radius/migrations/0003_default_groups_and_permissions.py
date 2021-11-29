# Manually Created

import django.db.models.deletion
import swapper
from django.db import migrations, models

from openwisp_radius.migrations import (
    add_default_group_to_existing_users,
    add_default_groups,
    add_default_organization,
    assign_permissions_to_groups,
)


class Migration(migrations.Migration):
    """
    Set default group and move existing
    users to the default group
    """

    rad_model = swapper.get_model_name('openwisp_radius', 'RadiusToken')
    users_model = swapper.get_model_name('openwisp_users', 'Organization')
    dependencies = [
        swapper.dependency('openwisp_radius', 'RadiusToken'),
        swapper.dependency(
            *swapper.split(rad_model), version='0002_initial_openwisp_app'
        ),
        swapper.dependency(*swapper.split(users_model), version='0004_default_groups'),
    ]

    operations = [
        migrations.RunPython(
            add_default_organization, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            add_default_groups, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            add_default_group_to_existing_users, reverse_code=migrations.RunPython.noop
        ),
        migrations.RunPython(
            assign_permissions_to_groups, reverse_code=migrations.RunPython.noop
        ),
        migrations.AlterField(
            model_name='nas',
            name='organization',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to=swapper.get_model_name('openwisp_users', 'Organization'),
                verbose_name='organization',
            ),
        ),
        migrations.AlterField(
            model_name='radiusaccounting',
            name='organization',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to=swapper.get_model_name('openwisp_users', 'Organization'),
                verbose_name='organization',
            ),
        ),
        migrations.AlterField(
            model_name='radiuscheck',
            name='organization',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to=swapper.get_model_name('openwisp_users', 'Organization'),
                verbose_name='organization',
            ),
        ),
        migrations.AlterField(
            model_name='radiuspostauth',
            name='organization',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to=swapper.get_model_name('openwisp_users', 'Organization'),
                verbose_name='organization',
            ),
        ),
        migrations.AlterField(
            model_name='radiusreply',
            name='organization',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to=swapper.get_model_name('openwisp_users', 'Organization'),
                verbose_name='organization',
            ),
        ),
    ]
