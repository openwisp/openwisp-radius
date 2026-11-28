"""Collect global and organization-scoped user registration metrics."""

from django.contrib.auth import get_user_model
from django.db.models import Count, F
from django.utils import timezone
from swapper import load_model

from ..utils import clean_registration_method

Metric = load_model("monitoring", "Metric")
RegisteredUser = load_model("openwisp_radius", "RegisteredUser")
OrganizationUser = load_model("openwisp_users", "OrganizationUser")
User = get_user_model()


def _get_user_signup_metric(organization_id, registration_method):
    metric, _ = Metric._get_or_create(
        configuration="user_signups",
        name="User SignUps",
        key="user_signups",
        object_id=None,
        content_type=None,
        extra_tags={
            "organization_id": str(organization_id),
            "method": registration_method,
        },
    )
    return metric


def _get_total_user_signup_metric(organization_id, registration_method):
    metric, _ = Metric._get_or_create(
        configuration="tot_user_signups",
        name="Total User SignUps",
        key="tot_user_signups",
        object_id=None,
        content_type=None,
        extra_tags={
            "organization_id": str(organization_id),
            "method": registration_method,
        },
    )
    return metric


def _write_user_signup_metric_for_all(metric_key):
    metric_data = []
    start_time = timezone.now() - timezone.timedelta(hours=1)
    end_time = timezone.now()
    if metric_key == "user_signups":
        get_metric_func = _get_user_signup_metric
    else:
        get_metric_func = _get_total_user_signup_metric
    # Get the total number of registered users
    registered_user_query = RegisteredUser.objects.exclude(
        user__date_joined__gt=end_time,
    )
    if metric_key == "user_signups":
        registered_user_query = registered_user_query.filter(
            user__date_joined__gt=start_time,
            user__date_joined__lte=end_time,
        )
    total_registered_users = dict(
        registered_user_query.values_list("method").annotate(
            count=Count("user", distinct=True)
        )
    )
    # Some manually created users, like superuser may not have a
    # RegisteredUser object. We would count them with "unspecified" method
    users_without_registereduser_query = User.objects.filter(
        registered_users__isnull=True
    )
    if metric_key == "user_signups":
        users_without_registereduser_query = users_without_registereduser_query.filter(
            date_joined__gt=start_time,
            date_joined__lte=end_time,
        )
    users_without_registereduser = users_without_registereduser_query.count()

    # Add the number of users which do not have a related RegisteredUser
    # to the number of users which registered using "unspecified" method.
    try:
        total_registered_users[""] = (
            total_registered_users[""] + users_without_registereduser
        )
    except KeyError:
        total_registered_users[""] = users_without_registereduser

    for method, count in total_registered_users.items():
        method = clean_registration_method(method)
        if method is None:
            continue
        metric = get_metric_func(organization_id="__all__", registration_method=method)
        metric_data.append((metric, {"value": count}))
    Metric.batch_write(metric_data)


def _write_user_signup_metrics_for_orgs(metric_key):
    metric_data = []
    start_time = timezone.now() - timezone.timedelta(hours=1)
    end_time = timezone.now()
    if metric_key == "user_signups":
        get_metric_func = _get_user_signup_metric
    else:
        get_metric_func = _get_total_user_signup_metric

    # Get registration data grouped by organization and registration method.
    # Scope OrganizationUser joins to the same organization as the
    # RegisteredUser to avoid memberships from other organizations affecting
    # this organization's signup metrics.
    registered_users_query = RegisteredUser.objects.exclude(
        method="pending_verification"
    ).exclude(
        user__openwisp_users_organizationuser__organization_id=F("organization_id"),
        user__openwisp_users_organizationuser__created__gt=end_time,
    )

    if metric_key == "user_signups":
        registered_users_query = registered_users_query.filter(
            user__openwisp_users_organizationuser__organization_id=F("organization_id"),
            user__openwisp_users_organizationuser__created__gt=start_time,
            user__openwisp_users_organizationuser__created__lte=end_time,
        )
    registered_users = registered_users_query.values_list(
        "organization_id",
        "method",
    ).annotate(count=Count("user_id", distinct=True))

    # Count users without a RegisteredUser for this organization.
    # A simple ``registered_users__isnull=True`` check would incorrectly
    # exclude users having RegisteredUser rows only in other organizations.
    users_without_registereduser_query = OrganizationUser.objects.exclude(
        user__registered_users__organization_id=F("organization_id")
    )
    if metric_key == "user_signups":
        users_without_registereduser_query = users_without_registereduser_query.filter(
            created__gt=start_time, created__lte=end_time
        )
    users_without_registereduser = dict(
        users_without_registereduser_query.values_list("organization_id").annotate(
            count=Count("user_id", distinct=True)
        )
    )

    for org_id, registration_method, count in registered_users:
        registration_method = clean_registration_method(registration_method)
        if registration_method == "unspecified":
            count += users_without_registereduser.pop(org_id, 0)
        metric = get_metric_func(
            organization_id=org_id, registration_method=registration_method
        )
        metric_data.append((metric, {"value": count}))

    # Write metrics for organizations having only users without a
    # RegisteredUser for that organization. These organizations are not
    # present in ``registered_users`` because they have no matching
    # RegisteredUser rows.
    for org_id, count in users_without_registereduser.items():
        metric = get_metric_func(
            organization_id=org_id, registration_method="unspecified"
        )
        metric_data.append((metric, {"value": count}))

    Metric.batch_write(metric_data)


def collect():
    _write_user_signup_metric_for_all(metric_key="user_signups")
    _write_user_signup_metric_for_all(metric_key="tot_user_signups")
    _write_user_signup_metrics_for_orgs(metric_key="user_signups")
    _write_user_signup_metrics_for_orgs(metric_key="tot_user_signups")
