import uuid
from collections import defaultdict

import swapper
from django.conf import settings
from django.contrib.auth.management import create_permissions
from django.contrib.auth.models import Permission

from ..utils import create_default_groups

BATCH_SIZE = 1000
REGISTERED_USER_ORGANIZATION_HELP_TEXT = (
    "The organization this registration info belongs to. "
    "If null, applies to all orgs without specific requirements."
)


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
    queryset = RegisteredUser.objects.order_by("user_id")
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
    queryset = RegisteredUserNew.objects.order_by(
        "user_id", "-is_verified", "method", "pk"
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
    RegisteredUser = apps.get_model(app_label, "RegisteredUser")
    if RegisteredUser._meta.swapped:
        return
    OrganizationUser = get_swapped_model(apps, "openwisp_users", "OrganizationUser")

    queryset = RegisteredUser.objects.filter(organization__isnull=True).order_by(
        "user_id"
    )
    iterator = queryset.iterator(chunk_size=BATCH_SIZE)
    for batch in _batched_iterator(iterator, BATCH_SIZE):
        user_ids = [registered_user.user_id for registered_user in batch]
        memberships = defaultdict(set)
        membership_qs = OrganizationUser.objects.filter(
            user_id__in=user_ids
        ).values_list("user_id", "organization_id")
        for user_id, organization_id in membership_qs.iterator(chunk_size=BATCH_SIZE):
            memberships[user_id].add(organization_id)

        existing_pairs = set(
            RegisteredUser.objects.filter(
                user_id__in=user_ids,
                organization__isnull=False,
            ).values_list("user_id", "organization_id")
        )

        to_create = []
        to_delete_pks = []
        for registered_user in batch:
            organization_ids = sorted(memberships.get(registered_user.user_id, ()))
            if not organization_ids:
                continue
            to_delete_pks.append(registered_user.pk)
            extra_kwargs = _registered_user_extra_kwargs(registered_user, extra_fields)
            for organization_id in organization_ids:
                pair = (registered_user.user_id, organization_id)
                if pair in existing_pairs:
                    continue
                existing_pairs.add(pair)
                copied = RegisteredUser(
                    id=uuid.uuid4(),
                    user_id=registered_user.user_id,
                    organization_id=organization_id,
                    is_verified=registered_user.is_verified,
                    method=registered_user.method,
                    **extra_kwargs,
                )
                copied.modified = registered_user.modified
                to_create.append(copied)

        _flush_bulk_create(RegisteredUser, to_create)
        if to_delete_pks:
            RegisteredUser.objects.filter(pk__in=to_delete_pks).delete()


def migrate_registered_users_multitenant_reverse(
    apps, schema_editor, app_label, extra_fields=()
):
    RegisteredUser = apps.get_model(app_label, "RegisteredUser")
    if RegisteredUser._meta.swapped:
        return

    user_ids_qs = (
        RegisteredUser.objects.filter(organization__isnull=False)
        .order_by()
        .values_list("user_id", flat=True)
        .distinct()
    )
    for user_id_batch in _batched_iterator(
        user_ids_qs.iterator(chunk_size=BATCH_SIZE), BATCH_SIZE
    ):
        existing_globals = set(
            RegisteredUser.objects.filter(
                user_id__in=user_id_batch,
                organization__isnull=True,
            ).values_list("user_id", flat=True)
        )
        org_records = RegisteredUser.objects.filter(
            user_id__in=user_id_batch,
            organization__isnull=False,
        ).order_by("user_id", "-is_verified", "method", "pk")

        to_create = []
        to_delete_pks = []
        current_user_id = None

        for registered_user in org_records.iterator(chunk_size=BATCH_SIZE):
            to_delete_pks.append(registered_user.pk)
            if registered_user.user_id == current_user_id:
                continue
            current_user_id = registered_user.user_id
            if registered_user.user_id in existing_globals:
                continue
            restored = RegisteredUser(
                id=uuid.uuid4(),
                user_id=registered_user.user_id,
                organization=None,
                is_verified=registered_user.is_verified,
                method=registered_user.method,
                **_registered_user_extra_kwargs(registered_user, extra_fields),
            )
            restored.modified = registered_user.modified
            to_create.append(restored)

        _flush_bulk_create(RegisteredUser, to_create)
        if to_delete_pks:
            RegisteredUser.objects.filter(pk__in=to_delete_pks).delete()


def delete_old_radius_token(apps, schema_editor):
    RadiusToken = get_swapped_model(apps, "openwisp_radius", "RadiusToken")
    RadiusToken.objects.all().delete()


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


def add_default_groups(apps, schema_editor):
    Organization = get_swapped_model(apps, "openwisp_users", "Organization")
    RadiusGroup = get_swapped_model(apps, "openwisp_radius", "RadiusGroup")
    for organization in Organization.objects.all():
        if not RadiusGroup.objects.filter(organization_id=organization.pk).exists():
            create_default_groups(organization, apps=apps)


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


def create_default_permissions(apps, schema_editor):
    for app_config in apps.get_app_configs():
        app_config.models_module = True
        create_permissions(app_config, apps=apps, verbosity=0)
        app_config.models_module = None


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


def populate_phonetoken_phone_number(apps, schema_editor):
    PhoneToken = get_swapped_model(apps, "openwisp_radius", "PhoneToken")
    for phone_token in PhoneToken.objects.all():
        phone_token.phone_number = phone_token.user.phone_number
        phone_token.save(update_fields=["phone_number"])
