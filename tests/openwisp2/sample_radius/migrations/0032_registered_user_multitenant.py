import uuid

import django
import django.db.models.deletion
import django.utils.timezone
import model_utils.fields
import swapper
from django.conf import settings
from django.db import migrations, models

from openwisp_radius.migrations import (
    REGISTERED_USER_ORGANIZATION_HELP_TEXT,
    copy_registered_users_ctcr_forward,
    copy_registered_users_ctcr_reverse,
    migrate_registered_users_multitenant_forward,
    migrate_registered_users_multitenant_reverse,
)
from openwisp_radius.registration import (
    REGISTRATION_METHOD_CHOICES,
    get_registration_choices,
)


def copy_registered_users_forward(apps, schema_editor):
    copy_registered_users_ctcr_forward(
        apps,
        schema_editor,
        app_label="sample_radius",
        extra_fields=("details",),
    )


def copy_registered_users_reverse(apps, schema_editor):
    copy_registered_users_ctcr_reverse(
        apps,
        schema_editor,
        app_label="sample_radius",
        extra_fields=("details",),
    )


def migrate_registered_users_forward(apps, schema_editor):
    migrate_registered_users_multitenant_forward(
        apps,
        schema_editor,
        app_label="sample_radius",
        extra_fields=("details",),
    )


def migrate_registered_users_reverse(apps, schema_editor):
    migrate_registered_users_multitenant_reverse(
        apps,
        schema_editor,
        app_label="sample_radius",
        extra_fields=("details",),
    )


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("sample_radius", "0031_radiusbatch_status"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.CreateModel(
                    name="RegisteredUserNew",
                    fields=[
                        (
                            "id",
                            models.UUIDField(
                                default=uuid.uuid4,
                                editable=False,
                                primary_key=True,
                                serialize=False,
                            ),
                        ),
                        (
                            "details",
                            models.CharField(
                                blank=True,
                                max_length=64,
                                null=True,
                            ),
                        ),
                        (
                            "method",
                            models.CharField(
                                blank=True,
                                choices=(
                                    REGISTRATION_METHOD_CHOICES
                                    if django.VERSION < (5, 0)
                                    else get_registration_choices
                                ),
                                default="",
                                help_text=(
                                    "users can sign up in different ways, some "
                                    "methods are valid as indirect identity "
                                    "verification (eg: mobile phone SIM card in "
                                    "most countries)"
                                ),
                                max_length=64,
                                verbose_name="registration method",
                            ),
                        ),
                        (
                            "is_verified",
                            models.BooleanField(
                                default=False,
                                help_text=(
                                    "whether the user has completed any identity "
                                    "verification process sucessfully"
                                ),
                                verbose_name="verified",
                            ),
                        ),
                        (
                            "modified",
                            model_utils.fields.AutoLastModifiedField(
                                default=django.utils.timezone.now,
                                editable=False,
                                verbose_name="Last verification change",
                            ),
                        ),
                        (
                            "user",
                            models.ForeignKey(
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="+",
                                to=settings.AUTH_USER_MODEL,
                            ),
                        ),
                        (
                            "organization",
                            models.ForeignKey(
                                blank=True,
                                help_text=REGISTERED_USER_ORGANIZATION_HELP_TEXT,
                                null=True,
                                on_delete=django.db.models.deletion.CASCADE,
                                related_name="+",
                                to=swapper.get_model_name(
                                    "openwisp_users", "Organization"
                                ),
                                verbose_name="organization",
                            ),
                        ),
                    ],
                    options={
                        "verbose_name": "Registration Information",
                        "verbose_name_plural": "Registration Information",
                    },
                ),
                migrations.RunPython(
                    copy_registered_users_forward,
                    copy_registered_users_reverse,
                ),
                migrations.DeleteModel(name="RegisteredUser"),
                migrations.RenameModel(
                    old_name="RegisteredUserNew",
                    new_name="RegisteredUser",
                ),
            ],
            state_operations=[
                migrations.AddField(
                    model_name="registereduser",
                    name="id",
                    field=models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                migrations.AlterField(
                    model_name="registereduser",
                    name="user",
                    field=models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="registered_users",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                migrations.AddField(
                    model_name="registereduser",
                    name="organization",
                    field=models.ForeignKey(
                        blank=True,
                        help_text=REGISTERED_USER_ORGANIZATION_HELP_TEXT,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="registered_users",
                        to=swapper.get_model_name("openwisp_users", "Organization"),
                        verbose_name="organization",
                    ),
                ),
            ],
        ),
        migrations.RunPython(
            migrate_registered_users_forward,
            migrate_registered_users_reverse,
        ),
        migrations.AddConstraint(
            model_name="registereduser",
            constraint=models.UniqueConstraint(
                fields=["user", "organization"],
                name="unique_registered_user_per_org",
            ),
        ),
        migrations.AddConstraint(
            model_name="registereduser",
            constraint=models.UniqueConstraint(
                fields=["user"],
                condition=models.Q(organization__isnull=True),
                name="unique_global_registered_user",
            ),
        ),
    ]
