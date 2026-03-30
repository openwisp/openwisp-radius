import uuid

import django
import django.db.models.deletion
import swapper
from django.conf import settings
from django.db import connection, migrations, models


def get_swapped_model(apps, app_name, model_name):
    model_path = swapper.get_model_name(app_name, model_name)
    app, model = swapper.split(model_path)
    return apps.get_model(app, model)


def recreate_table_forward(apps, schema_editor):
    """
    Recreate registereduser table with new schema:
    - UUID id as primary key
    - user as ForeignKey (not primary key)
    - organization as nullable ForeignKey
    Then copy data from old table.
    """
    RegisteredUser = get_swapped_model(apps, "openwisp_radius", "RegisteredUser")
    db_table = RegisteredUser._meta.db_table
    User = apps.get_model(settings.AUTH_USER_MODEL)
    user_table = User._meta.db_table

    with connection.cursor() as cursor:
        # Read existing data (sample_radius model has extra 'details' field)
        cursor.execute(
            f'SELECT "user_id", "is_verified", "method", "modified", "details" '
            f'FROM "{db_table}"'
        )
        existing_data = cursor.fetchall()

        # Drop old table
        cursor.execute(f'DROP TABLE IF EXISTS "{db_table}"')

        vendor = connection.vendor
        if vendor == "sqlite":
            cursor.execute(
                f'CREATE TABLE "{db_table}" ('
                f'"id" char(32) NOT NULL PRIMARY KEY, '
                f'"user_id" integer NOT NULL REFERENCES "{user_table}" ("id") '
                f"DEFERRABLE INITIALLY DEFERRED, "
                f'"is_verified" bool NOT NULL, '
                f'"method" varchar(16) NOT NULL, '
                f'"modified" datetime NULL, '
                f'"details" varchar(64) NULL, '
                f'"organization_id" char(32) NULL REFERENCES '
                f'"openwisp_users_organization" ("id") '
                f"DEFERRABLE INITIALLY DEFERRED"
                f")"
            )
        else:
            cursor.execute(
                f'CREATE TABLE "{db_table}" ('
                f'"id" uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(), '
                f'"user_id" integer NOT NULL REFERENCES "{user_table}" ("id") '
                f"DEFERRABLE INITIALLY DEFERRED, "
                f'"is_verified" boolean NOT NULL, '
                f'"method" varchar(16) NOT NULL, '
                f'"modified" timestamp with time zone NULL, '
                f'"details" varchar(64) NULL, '
                f'"organization_id" uuid NULL REFERENCES '
                f'"openwisp_users_organization" ("id") '
                f"DEFERRABLE INITIALLY DEFERRED"
                f")"
            )

        # Create indexes
        cursor.execute(
            f'CREATE INDEX "{db_table}_user_id_idx" ON "{db_table}" ("user_id")'
        )
        cursor.execute(
            f'CREATE INDEX "{db_table}_org_id_idx" ON "{db_table}" ("organization_id")'
        )

        # Re-insert data (all as global records initially)
        for user_id, is_verified, method, modified, details in existing_data:
            new_id = uuid.uuid4().hex if vendor == "sqlite" else str(uuid.uuid4())
            cursor.execute(
                f'INSERT INTO "{db_table}" '
                f'("id", "user_id", "is_verified", "method", "modified", '
                f'"details", "organization_id") VALUES (%s, %s, %s, %s, %s, %s, %s)',
                [new_id, user_id, is_verified, method, modified, details, None],
            )


def migrate_registered_users_forward(apps, schema_editor):
    """
    For each existing RegisteredUser (global), find all OrganizationUser
    records for that user and create one RegisteredUser per organization.
    """
    RegisteredUser = get_swapped_model(apps, "openwisp_radius", "RegisteredUser")
    OrganizationUser = get_swapped_model(apps, "openwisp_users", "OrganizationUser")

    for reg_user in RegisteredUser.objects.filter(organization__isnull=True):
        org_users = OrganizationUser.objects.filter(user_id=reg_user.user_id)
        if org_users.exists():
            for org_user in org_users:
                if not RegisteredUser.objects.filter(
                    user_id=reg_user.user_id,
                    organization_id=org_user.organization_id,
                ).exists():
                    RegisteredUser.objects.create(
                        id=uuid.uuid4(),
                        user_id=reg_user.user_id,
                        organization_id=org_user.organization_id,
                        is_verified=reg_user.is_verified,
                        method=reg_user.method,
                    )
            # Delete the original global record since we now have org-specific ones
            reg_user.delete()


def migrate_registered_users_reverse(apps, schema_editor):
    """
    Reverse migration: consolidate per-org records back to global.
    """
    RegisteredUser = get_swapped_model(apps, "openwisp_radius", "RegisteredUser")

    user_ids = (
        RegisteredUser.objects.filter(organization__isnull=False)
        .values_list("user_id", flat=True)
        .distinct()
    )
    for user_id in user_ids:
        org_records = RegisteredUser.objects.filter(
            user_id=user_id, organization__isnull=False
        ).order_by("-is_verified", "method")
        best = org_records.first()
        if best:
            global_exists = RegisteredUser.objects.filter(
                user_id=user_id, organization__isnull=True
            ).exists()
            if not global_exists:
                RegisteredUser.objects.create(
                    id=uuid.uuid4(),
                    user_id=user_id,
                    organization=None,
                    is_verified=best.is_verified,
                    method=best.method,
                )
            org_records.delete()


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("0031_radiusbatch_status", "0042_set_existing_batches_completed"),
    ]

    operations = [
        # Step 1: Recreate the table with new schema (UUID pk, ForeignKey user, organization)
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(
                    recreate_table_forward,
                    migrations.RunPython.noop,
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
                        help_text=(
                            "The organization this registration info belongs to. "
                            "If null, applies to all orgs without specific requirements."
                        ),
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="registered_users",
                        to="openwisp_users.organization",
                        verbose_name="organization",
                    ),
                ),
            ],
        ),
        # Step 2: Data migration - create per-org records
        migrations.RunPython(
            migrate_registered_users_forward,
            migrate_registered_users_reverse,
        ),
        # Step 3: Add unique constraints
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
                condition=models.Q(("organization__isnull", True)),
                fields=["user"],
                name="unique_global_registered_user",
            ),
        ),
    ]
