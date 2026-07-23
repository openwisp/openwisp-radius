import uuid

import swapper
from django.conf import settings
from django.contrib.auth.management import create_permissions
from django.contrib.auth.models import Permission
from django.db.models import Case, Exists, IntegerField, OuterRef, Prefetch, Value, When

from ..utils import create_default_groups

BATCH_SIZE = 1000


def get_swapped_model(apps, app_name, model_name):
    model_path = swapper.get_model_name(app_name, model_name)
    app, model = swapper.split(model_path)
    return apps.get_model(app, model)


def _batched_iterator(iterator, batch_size=BATCH_SIZE):
    batch = []
    for item in iterator:
        batch.append(item)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _flush_bulk_create(model, objects, batch_size=BATCH_SIZE):
    if objects:
        model.objects.bulk_create(objects, batch_size=batch_size)
        objects.clear()


def _registered_user_extra_kwargs(registered_user, extra_fields=()):
    return {
        field_name: getattr(registered_user, field_name) for field_name in extra_fields
    }


def _filter_valid_registered_users(queryset, apps):
    """
    Return RegisteredUser rows whose related user still exists.

    It can happen that database can contain dangling user references. The copy helpers
    call this before bulk inserts so later foreign-key checks do not fail.
    """
    User = apps.get_model(settings.AUTH_USER_MODEL)
    existing_user = User.objects.filter(pk=OuterRef("user_id"))
    return queryset.annotate(user_exists=Exists(existing_user)).filter(user_exists=True)


def _filter_valid_organization_memberships(queryset, apps):
    """
    Return OrganizationUser rows whose user and organization still exist.

    The multitenant RegisteredUser migration and the PhoneToken backfill both
    reuse OrganizationUser foreign keys. Filtering dangling memberships here
    prevents later inserts and updates from writing broken references.
    """
    User = apps.get_model(settings.AUTH_USER_MODEL)
    Organization = get_swapped_model(apps, "openwisp_users", "Organization")
    existing_user = User.objects.filter(pk=OuterRef("user_id"))
    existing_organization = Organization.objects.filter(pk=OuterRef("organization_id"))
    return queryset.annotate(
        user_exists=Exists(existing_user),
        organization_exists=Exists(existing_organization),
    ).filter(
        user_exists=True,
        organization_exists=True,
    )


def _registered_user_method_priority_case():
    # Strong methods (anything that is not '' or 'email') must rank above the
    # weak fallbacks so rollback restores the strongest verification state.
    return Case(
        When(method="pending_verification", then=Value(-1)),
        When(method="", then=Value(0)),
        When(method="email", then=Value(1)),
        default=Value(2),
        output_field=IntegerField(),
    )


def copy_registered_users_ctcr_forward(
    apps,
    schema_editor,
    app_label,
    new_model_name="RegisteredUserNew",
    extra_fields=(),
):
    RegisteredUser = apps.get_model(app_label, "RegisteredUser")
    RegisteredUserNew = apps.get_model(app_label, new_model_name)
    if RegisteredUser._meta.swapped:
        return

    new_objects = []
    queryset = _filter_valid_registered_users(
        RegisteredUser.objects,
        apps,
    ).order_by("user_id")
    for registered_user in queryset.iterator(chunk_size=BATCH_SIZE):
        copied = RegisteredUserNew(
            id=uuid.uuid4(),
            user_id=registered_user.user_id,
            organization=None,
            method=registered_user.method,
            is_verified=registered_user.is_verified,
            **_registered_user_extra_kwargs(registered_user, extra_fields),
        )
        copied.modified = registered_user.modified
        new_objects.append(copied)
        if len(new_objects) >= BATCH_SIZE:
            _flush_bulk_create(RegisteredUserNew, new_objects)
    _flush_bulk_create(RegisteredUserNew, new_objects)


def copy_registered_users_ctcr_reverse(
    apps,
    schema_editor,
    app_label,
    new_model_name="RegisteredUserNew",
    extra_fields=(),
):
    RegisteredUser = apps.get_model(app_label, "RegisteredUser")
    RegisteredUserNew = apps.get_model(app_label, new_model_name)
    if RegisteredUser._meta.swapped:
        return

    restored_objects = []
    previous_user_id = None
    # Annotate each row with an explicit verification priority so that stronger
    # methods (anything that is not '' or 'email') sort before weaker ones.
    # Lexical ordering of 'method' would place '' first, picking the weakest.
    method_priority = _registered_user_method_priority_case()
    queryset = (
        _filter_valid_registered_users(
            RegisteredUserNew.objects,
            apps,
        )
        .annotate(method_priority=method_priority)
        .order_by("user_id", "-is_verified", "-method_priority", "-modified")
    )
    for registered_user in queryset.iterator(chunk_size=BATCH_SIZE):
        if registered_user.user_id == previous_user_id:
            continue
        previous_user_id = registered_user.user_id
        restored = RegisteredUser(
            user_id=registered_user.user_id,
            method=registered_user.method,
            is_verified=registered_user.is_verified,
            **_registered_user_extra_kwargs(registered_user, extra_fields),
        )
        restored.modified = registered_user.modified
        restored_objects.append(restored)
        if len(restored_objects) >= BATCH_SIZE:
            _flush_bulk_create(RegisteredUser, restored_objects)
    _flush_bulk_create(RegisteredUser, restored_objects)


def migrate_registered_users_multitenant_forward(
    apps, schema_editor, app_label, extra_fields=()
):
    """
    Expand legacy org-less RegisteredUser rows into organization-specific rows.

    Before this migration, RegisteredUser is effectively single-tenant and users
    are expected to have at most one row where organization IS NULL. That row is
    treated as the template for all organization-specific rows created during the
    migration.

    For each user, the migration:
    1. Finds the org-less RegisteredUser row.
    2. Creates one RegisteredUser per OrganizationUser membership.
    3. Deletes the original org-less row.

    Implementation notes:
    - Assumes each user has at most one org-less RegisteredUser row.
    - Prioritizes readability and explicit control flow over aggressive SQL/JOIN
    optimization.
    - Avoids JOIN-based filtering to keep migration assumptions visible in Python
    and reduce duplicate-row/DISTINCT complexity.
    - Uses iterator(), prefetch_related(), bulk_create(), and batched deletes to
    remain memory bounded while processing large datasets.
    """
    User = apps.get_model(settings.AUTH_USER_MODEL)
    RegisteredUser = apps.get_model(
        app_label,
        "RegisteredUser",
    )
    OrganizationUser = get_swapped_model(
        apps,
        "openwisp_users",
        "OrganizationUser",
    )
    # Ignore memberships that would copy broken foreign keys into the new
    # multitenant RegisteredUser rows.
    valid_memberships = _filter_valid_organization_memberships(
        OrganizationUser.objects.only(
            "user_id",
            "organization_id",
        ),
        apps,
    )

    queryset = User.objects.prefetch_related(
        Prefetch(
            "registered_users",
            queryset=RegisteredUser.objects.only(
                "id",
                "user_id",
                "organization_id",
                "method",
                "is_verified",
                "modified",
                *extra_fields,
            ),
            # Store prefetched objects directly as a Python list to avoid
            # additional queryset evaluation during iteration.
            to_attr="prefetched_registered_users",
        ),
        Prefetch(
            "openwisp_users_organizationuser",
            queryset=valid_memberships,
            to_attr="organization_memberships",
        ),
    ).order_by("id")

    to_create = []
    for user in queryset.iterator(chunk_size=BATCH_SIZE):
        # Locate the legacy org-less RegisteredUser row that acts as the source
        # template for new organization-specific rows.
        #
        # We intentionally do this in Python instead of SQL because:
        #
        # - the prefetched list is expected to be extremely small
        #   (ideally, it will contain at most one item due to the migration invariant)
        # - it keeps migration assumptions explicit,
        # - and avoids introducing JOIN + DISTINCT complexity.
        base_registered_user = next(
            (
                registered_user
                for registered_user in user.prefetched_registered_users
                if registered_user.organization_id is None
            ),
            None,
        )
        # Users without a legacy org-less RegisteredUser row require no work.
        if not base_registered_user:
            continue

        # Create one RegisteredUser row per organization membership.
        for membership in user.organization_memberships:
            copied = RegisteredUser(
                id=uuid.uuid4(),
                user_id=user.id,
                organization_id=membership.organization_id,
                method=base_registered_user.method,
                is_verified=base_registered_user.is_verified,
                **_registered_user_extra_kwargs(
                    base_registered_user,
                    extra_fields,
                ),
            )
            # Preserve the original modification timestamp because this migration
            # reshapes existing data rather than creating a logically new
            # verification state.
            copied.modified = base_registered_user.modified
            to_create.append(copied)

        # Flush inserts in batches to avoid holding too many unsaved model
        # instances in memory.
        if len(to_create) >= BATCH_SIZE:
            _flush_bulk_create(
                RegisteredUser,
                to_create,
            )

    _flush_bulk_create(
        RegisteredUser,
        to_create,
    )

    # Delete all remaining legacy org-less RegisteredUser rows.
    #
    # This covers:
    #   1. Users whose org-less row was expanded into org-specific rows above.
    #   2. Users with an org-less row but zero organization memberships.
    #      These users have no org-specific rows to migrate to, and keeping
    #      an org-less row would violate the new (user, organization) unique
    #      constraint, so the row is intentionally cleaned up here.
    RegisteredUser.objects.filter(
        organization__isnull=True,
    ).delete()


def migrate_registered_users_multitenant_reverse(
    apps, schema_editor, app_label, extra_fields=()
):
    # Keep the strongest RegisteredUser per user and delete the weaker duplicates.
    # Ranking is by: verified over unverified, stronger method over weaker method,
    # then newer modified timestamps over older ones.
    RegisteredUser = apps.get_model(app_label, "RegisteredUser")
    # Process users in batches so the migration scales to large tables without
    # issuing one query per user.
    user_ids_qs = (
        RegisteredUser.objects.order_by().values_list("user_id", flat=True).distinct()
    )
    for user_id_batch in _batched_iterator(
        user_ids_qs.iterator(chunk_size=BATCH_SIZE), BATCH_SIZE
    ):
        # Annotate each row with an explicit verification priority so that stronger
        # methods (anything that is not '' or 'email') sort before weaker ones.
        method_priority = _registered_user_method_priority_case()
        ranked_registered_users = (
            RegisteredUser.objects.filter(
                user_id__in=user_id_batch,
            )
            .annotate(method_priority=method_priority)
            .order_by("user_id", "-is_verified", "-method_priority", "-modified")
        )
        to_delete_pks = []
        current_user_id = None
        for registered_user in ranked_registered_users.iterator(chunk_size=BATCH_SIZE):
            # Rows for the same user are consecutive because of the ordering
            # above, and the first row in each group is the strongest one.
            # Every later row for that user is therefore a weaker duplicate.
            is_duplicate_for_user = registered_user.user_id == current_user_id
            if is_duplicate_for_user:
                to_delete_pks.append(registered_user.pk)
            else:
                current_user_id = registered_user.user_id
                if len(to_delete_pks) >= BATCH_SIZE:
                    RegisteredUser.objects.filter(pk__in=to_delete_pks).delete()
                    to_delete_pks.clear()

        # Delete all weaker rows for the batch at once rather than issuing a
        # separate delete for each user.
        if to_delete_pks:
            RegisteredUser.objects.filter(pk__in=to_delete_pks).delete()


# Flagged for removal (#705): data migration for the squashed 0001-0042 range
# (released <= 1.2.x). Remove in the future cleanup that deletes the original
# 0001-0042 files and drops their RunPython steps from the squashed migration.
def delete_old_radius_token(apps, schema_editor):
    RadiusToken = get_swapped_model(apps, "openwisp_radius", "RadiusToken")
    RadiusToken.objects.all().delete()


# Flagged for removal (#705): data migration for the squashed 0001-0042 range
# (released <= 1.2.x). Remove in the future cleanup that deletes the original
# 0001-0042 files and drops their RunPython steps from the squashed migration.
def add_default_organization(apps, schema_editor):
    """
    Set default organization using
    settings._OPENWISP_DEFAULT_ORG_UUID
    """
    models = ["nas", "radiusaccounting", "radiuscheck", "radiuspostauth", "radiusreply"]
    if hasattr(settings, "_OPENWISP_DEFAULT_ORG_UUID"):
        default_org_id = settings._OPENWISP_DEFAULT_ORG_UUID
    else:  # pragma: no-cover (corner case)
        Organization = get_swapped_model(apps, "openwisp_users", "Organization")
        default_org_id = Organization.objects.first().pk
    for model in models:
        Model = get_swapped_model(apps, "openwisp_radius", model)
        for record in Model.objects.all().iterator():
            record.organization_id = default_org_id
            record.save()

    OrganizationRadiusSettings = get_swapped_model(
        apps, "openwisp_radius", "organizationradiussettings"
    )
    OrganizationRadiusSettings.objects.create(organization_id=default_org_id)


# Flagged for removal (#705): data migration for the squashed 0001-0042 range
# (released <= 1.2.x). Remove in the future cleanup that deletes the original
# 0001-0042 files and drops their RunPython steps from the squashed migration.
def add_default_groups(apps, schema_editor):
    Organization = get_swapped_model(apps, "openwisp_users", "Organization")
    RadiusGroup = get_swapped_model(apps, "openwisp_radius", "RadiusGroup")
    for organization in Organization.objects.all():
        if not RadiusGroup.objects.filter(organization_id=organization.pk).exists():
            create_default_groups(organization, apps=apps)


# Flagged for removal (#705): data migration for the squashed 0001-0042 range
# (released <= 1.2.x). Remove in the future cleanup that deletes the original
# 0001-0042 files and drops their RunPython steps from the squashed migration.
def add_default_group_to_existing_users(apps, schema_editor):
    Organization = get_swapped_model(apps, "openwisp_users", "Organization")
    OrganizationUser = get_swapped_model(apps, "openwisp_users", "OrganizationUser")
    RadiusUserGroup = get_swapped_model(apps, "openwisp_radius", "RadiusUserGroup")
    RadiusGroup = get_swapped_model(apps, "openwisp_radius", "RadiusGroup")
    for organization in Organization.objects.all():
        default_group = RadiusGroup.objects.filter(
            organization_id=organization.pk, default=True
        )
        if default_group.exists():
            default_group = default_group.first()
            for orguser in OrganizationUser.objects.filter(
                organization_id=organization.pk
            ):
                user = orguser.user
                if not RadiusUserGroup.objects.filter(user=user).exists():
                    user_group = RadiusUserGroup(
                        user_id=user.id,
                        username=user.username,
                        group_id=default_group.id,
                    )
                    user_group.save()


# Flagged for removal (#705): helper for assign_permissions_to_groups, used only
# by the squashed 0001-0042 range (released <= 1.2.x). Remove in the future
# cleanup that deletes the original 0001-0042 files and drops their RunPython
# steps from the squashed migration.
def create_default_permissions(apps, schema_editor):
    for app_config in apps.get_app_configs():
        app_config.models_module = True
        create_permissions(app_config, apps=apps, verbosity=0)
        app_config.models_module = None


# Flagged for removal (#705): data migration for the squashed 0001-0042 range
# (released <= 1.2.x). Remove in the future cleanup that deletes the original
# 0001-0042 files and drops their RunPython steps from the squashed migration.
def assign_permissions_to_groups(apps, schema_editor):
    create_default_permissions(apps, schema_editor)
    Group = get_swapped_model(apps, "openwisp_users", "Group")

    try:
        admin = Group.objects.get(name="Administrator")
        operator = Group.objects.get(name="Operator")
    # consider failures custom cases
    # that do not have to be dealt with
    except Group.DoesNotExist:
        return

    operators_and_admins_can_manage = ["radiuspostauth", "radiusaccounting"]
    operators_read_only_admins_manage = [
        "radiuscheck",
        "radiusreply",
        "radiusgroup",
        "radiusgroupcheck",
        "radiusgroupreply",
        "radiususergroup",
        "nas",
        "radiusbatch",
        "organizationradiussettings",
    ]
    manage_operations = ["add", "change", "delete"]

    for action in manage_operations:
        for model_name in operators_and_admins_can_manage:
            permission = Permission.objects.get(codename=f"{action}_{model_name}")
            admin.permissions.add(permission.pk)
            operator.permissions.add(permission.pk)
    for model_name in operators_read_only_admins_manage:
        try:
            permission = Permission.objects.get(codename=f"view_{model_name}")
            operator.permissions.add(permission.pk)
        except Permission.DoesNotExist:
            pass
        for action in manage_operations:
            permission_ad = Permission.objects.get(codename=f"{action}_{model_name}")
            admin.permissions.add(permission_ad.pk)


# Flagged for removal (#705): data migration for the squashed 0001-0042 range
# (released <= 1.2.x). Remove in the future cleanup that deletes the original
# 0001-0042 files and drops their RunPython steps from the squashed migration.
def popluate_uuids(apps, schema_editor):
    models = [
        "RadiusCheck",
        "RadiusReply",
        "RadiusGroupCheck",
        "RadiusGroupReply",
        "RadiusUserGroup",
        "RadiusPostAuth",
        "Nas",
    ]
    for model in models:
        model = get_swapped_model(apps, "openwisp_radius", model)
        for obj in model.objects.all():
            obj.uuid = uuid.uuid4()
            obj.save(update_fields=["uuid"])


# Flagged for removal (#705): data migration for the squashed 0001-0042 range
# (released <= 1.2.x). Remove in the future cleanup that deletes the original
# 0001-0042 files and drops their RunPython steps from the squashed migration.
def populate_phonetoken_phone_number(apps, schema_editor):
    PhoneToken = get_swapped_model(apps, "openwisp_radius", "PhoneToken")
    for phone_token in PhoneToken.objects.all():
        phone_token.phone_number = phone_token.user.phone_number
        phone_token.save(update_fields=["phone_number"])


def _get_first_valid_membership_organization_id(
    user_id,
    OrganizationUser,
    apps,
):
    """Return the first organization id from a user's valid memberships."""
    queryset = _filter_valid_organization_memberships(
        OrganizationUser.objects.filter(
            user_id=user_id,
        ),
        apps,
    )
    return (
        queryset.order_by("created", "pk")
        .values_list("organization_id", flat=True)
        .first()
    )


def populate_phonetoken_organization(
    apps,
    schema_editor,
    app_label="openwisp_radius",
):
    """Populate PhoneToken.organization_id from the user's first organization.

    For each user that has PhoneToken rows with a null organization_id,
    find the user's first OrganizationUser membership (ordered by created, pk)
    and set that organization_id on all their PhoneToken records that are
    still null.

    Any rows that cannot be resolved to an organization are
    discarded before the later NOT NULL migration step.

    Operates using the provided apps registry (for migrations).

    Args:
        apps: Django apps registry passed to migrations functions.
        schema_editor: Schema editor passed to migrations functions (unused).
        app_label: App label to load the PhoneToken model from.
    """
    PhoneToken = apps.get_model(app_label, "PhoneToken")
    OrganizationUser = get_swapped_model(
        apps,
        "openwisp_users",
        "OrganizationUser",
    )
    user_ids = (
        PhoneToken.objects.filter(
            organization_id__isnull=True,
        )
        .order_by()
        .values_list("user_id", flat=True)
        .distinct()
    )
    for user_id in user_ids.iterator(chunk_size=BATCH_SIZE):
        organization_id = _get_first_valid_membership_organization_id(
            user_id,
            OrganizationUser,
            apps,
        )
        if organization_id is None:
            continue
        PhoneToken.objects.filter(
            user_id=user_id,
            organization_id__isnull=True,
        ).update(
            organization_id=organization_id,
        )
    PhoneToken.objects.filter(organization_id__isnull=True).delete()
