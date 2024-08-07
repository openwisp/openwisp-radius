from django.db import migrations

from openwisp_utils.fields import FallbackMixin

from ..utils import load_model


def clean_fallback_fields(apps, schema_editor):
    """
    This data migration is necessary to clean up the database
    from unnecessary stored fallback values. In the previous
    implementation, the fallback value was stored in the database.
    However, this was not the intended behavior and was a bug. This migration
    sets the fallback fields to None when the value in the database
    is the same as the fallback value, effectively removing the
    unnecessary data from the database.
    """
    OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
    fallback_fields = []
    fallback_field_names = []

    for field in OrganizationRadiusSettings._meta.get_fields():
        if isinstance(field, FallbackMixin):
            fallback_fields.append(field)
            fallback_field_names.append(field.name)
    updated_settings = []
    for radius_settings in OrganizationRadiusSettings.objects.iterator():
        changed = False
        for field in fallback_fields:
            if getattr(radius_settings, field.name) == field.fallback:
                setattr(radius_settings, field.name, None)
                changed = True
        if changed:
            updated_settings.append(radius_settings)

        if len(updated_settings) > 100:
            OrganizationRadiusSettings.objects.bulk_update(
                updated_settings, fields=[field.name for field in fallback_fields]
            )
            updated_settings = []

    if updated_settings:
        OrganizationRadiusSettings.objects.bulk_update(
            updated_settings, fields=[field.name for field in fallback_fields]
        )


class Migration(migrations.Migration):
    dependencies = [
        (
            'openwisp_radius',
            '0037_alter_organizationradiussettings_allowed_mobile_prefixes_and_more',
        ),
    ]

    operations = [
        migrations.RunPython(
            clean_fallback_fields, reverse_code=migrations.RunPython.noop
        ),
    ]
