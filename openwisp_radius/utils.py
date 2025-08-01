import csv
import logging
import os
from datetime import timedelta
from io import BytesIO, StringIO

import swapper
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.core.validators import validate_email
from django.template.loader import get_template
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import APIException
from sendsms.message import SmsMessage as BaseSmsMessage
from sendsms.signals import sms_post_send
from weasyprint import HTML

from . import settings as app_settings

SESSION_TIME_ATTRIBUTE = "Max-Daily-Session"
SESSION_TRAFFIC_ATTRIBUTE = "Max-Daily-Session-Traffic"
DEFAULT_SESSION_TIME_LIMIT = "10800"  # seconds
DEFAULT_SESSION_TRAFFIC_LIMIT = "3000000000"  # bytes (octets)

logger = logging.getLogger(__name__)


def load_model(model):
    return swapper.load_model("openwisp_radius", model)


def get_model(apps, model_path):
    app, model = model_path.split(".")
    return apps.get_model(app, model)


def get_swapped_model(apps, app_name, model_name):
    model_path = swapper.get_model_name(app_name, model_name)
    return get_model(apps, model_path)


def create_default_groups(organization, apps=None):
    if apps is not None:
        RadiusGroup = get_swapped_model(apps, "openwisp_radius", "RadiusGroup")
        RadiusGroupCheck = get_swapped_model(
            apps, "openwisp_radius", "RadiusGroupCheck"
        )
    else:
        RadiusGroup = load_model("RadiusGroup")
        RadiusGroupCheck = load_model("RadiusGroupCheck")
    default = RadiusGroup(
        organization_id=organization.pk,
        name=f"{organization.slug}-users",
        description="Regular users",
        default=True,
    )
    default.save()
    check = RadiusGroupCheck(
        group_id=default.id,
        groupname=default.name,
        attribute=SESSION_TIME_ATTRIBUTE,
        op=":=",
        value=DEFAULT_SESSION_TIME_LIMIT,
    )
    check.save()
    check = RadiusGroupCheck(
        group_id=default.id,
        groupname=default.name,
        attribute=SESSION_TRAFFIC_ATTRIBUTE,
        op=":=",
        value=DEFAULT_SESSION_TRAFFIC_LIMIT,
    )
    check.save()
    power_users = RadiusGroup(
        organization_id=organization.pk,
        name=f"{organization.slug}-power-users",
        description="Users with less restrictions",
        default=False,
    )
    power_users.save()


def get_sms_default_valid_until():
    delta = timedelta(minutes=app_settings.SMS_TOKEN_DEFAULT_VALIDITY)
    return timezone.now() + delta


def generate_sms_token():
    length = app_settings.SMS_TOKEN_LENGTH
    hash_algorithm = app_settings.SMS_TOKEN_HASH_ALGORITHM
    hash_ = hash_algorithm()
    hash_.update(settings.SECRET_KEY.encode("utf-8"))
    hash_.update(os.urandom(16))
    token = str(int(hash_.hexdigest(), 16))[-length:]
    return token


class SmsMessage(BaseSmsMessage):
    def send(self, fail_silently=False, meta_data=None):
        """
        Customized send method that allows passing
        custom meta data configuration to the SMS backend
        """
        if not self.to:
            return 0
        backend_instance = self.get_connection(fail_silently)
        args = [[self]]
        if meta_data and getattr(backend_instance, "supports_meta_data", False):
            args.append(meta_data)
        res = backend_instance.send_messages(*args)
        sms_post_send.send(
            sender=self, to=self.to, from_phone=self.from_phone, body=self.body
        )
        return res


def find_available_username(username, users_list, prefix=False):
    User = get_user_model()
    suffix = 1
    tmp = f"{username}{suffix}" if prefix else username
    names_list = map(lambda x: x.username, users_list)
    while User.objects.filter(username=tmp).exists() or tmp in names_list:
        suffix += 1 if prefix else 0
        tmp = f"{username}{suffix}"
        suffix += 1 if not prefix else 0
    return tmp


def get_encoding_format(byte_data):
    # Explicitly handle some common encodings, including utf-16le
    common_encodings = ["utf-8-sig", "utf-16", "utf-16be", "utf-16le", "ascii"]

    for enc in common_encodings:
        try:
            byte_data.decode(enc)
            return enc
        except (UnicodeDecodeError, TypeError):
            continue

    return "utf-8"


def decode_byte_data(data):
    if isinstance(data, bytes):
        data = data.decode(get_encoding_format(data))
        data = data.replace("\x00", "")  # Removing null bytes
    return data


def validate_csvfile(csvfile):
    csv_data = csvfile.read()

    try:
        csv_data = decode_byte_data(csv_data)
    except UnicodeDecodeError:
        raise ValidationError(
            _(
                "Unrecognized file format, the supplied file "
                "does not look like a CSV file."
            )
        )

    reader = csv.reader(StringIO(csv_data), delimiter=",")
    error_message = "The CSV contains a line with invalid data,\
                    line number {} triggered the following error: {}"
    row_count = 1
    for row in reader:
        if len(row) == 5:
            username, password, email, firstname, lastname = row
            try:
                validate_email(email)
            except ValidationError as error:
                raise ValidationError(
                    _(error_message.format(str(row_count), error.message))
                )
            row_count += 1
        elif len(row) > 0:
            raise ValidationError(
                _(error_message.format(str(row_count), "Improper CSV format."))
            )
    csvfile.seek(0)


def prefix_generate_users(prefix, n, password_length):
    users_list = []
    user_password = []
    User = get_user_model()
    for i in range(n):
        username = find_available_username(prefix, users_list, True)
        password = get_random_string(length=password_length)
        u = User(username=username)
        u.set_password(password)
        users_list.append(u)
        user_password.append([username, password])
    return users_list, user_password


def generate_pdf(radbatch_uuid):
    template = get_template(app_settings.BATCH_PDF_TEMPLATE)
    data = load_model("RadiusBatch").objects.get(pk=radbatch_uuid)
    html = HTML(string=template.render({"users": data.user_credentials}))
    buffer = BytesIO()
    html.write_pdf(target=buffer)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf


def update_user_related_records(sender, instance, created, **kwargs):
    if created:
        return
    instance.radiususergroup_set.update(username=instance.username)
    instance.radiuscheck_set.update(username=instance.username)
    instance.radiusreply_set.update(username=instance.username)


def get_organization_radius_settings(organization, radius_setting):
    try:
        return getattr(organization.radius_settings, radius_setting)
    except ObjectDoesNotExist:
        logger.exception(
            f"Got exception while accessing radius_settings for {organization.name}"
        )
        raise APIException(
            _("Could not complete operation because of an internal misconfiguration")
        )


def get_user_group(user, organization_id):
    """
    Retrieves the first user group for a given user and organization_id based
    on RadiusUserGroup.priority.

    Args:
        user (User): The user for which to retrieve the group.
        organization_id (uuid): The ID of the organization.

    Returns:
        UserGroup or None: The user group associated with the user and organization ID,
        or None if no group is found.
    """
    return (
        user.radiususergroup_set.filter(group__organization_id=organization_id)
        .select_related("group")
        .order_by("priority")
        .first()
    )


def get_group_checks(group):
    """
    Retrieves a dictionary of checks for the given group.

    Parameters:
        group (Group): The group object for which to retrieve the checks.

    Returns:
        dict: A dictionary of group checks with the attribute as the key and
        the corresponding group check object as the value.

    Used to query the DB for group checks only once
    instead of once per each counter in use.
    """

    if not app_settings.COUNTERS:
        return

    check_attributes = app_settings.CHECK_ATTRIBUTE_COUNTERS_MAP.keys()
    group_checks = group.radiusgroupcheck_set.filter(attribute__in=check_attributes)
    result = {}
    for group_check in group_checks:
        result[group_check.attribute] = group_check
    return result


def get_one_time_login_url(user, organization):
    if "sesame.backends.ModelBackend" not in getattr(
        settings, "AUTHENTICATION_BACKENDS", []
    ):
        return
    from sesame.utils import get_query_string

    try:
        org_radius_settings = organization.radius_settings
    except ObjectDoesNotExist:
        logger.warning(
            f'Organization "{organization.name}" does not '
            "have any OpenWISP RADIUS settings configured"
        )
        return

    login_url = org_radius_settings.login_url
    if not login_url:
        logger.debug(f"login_url is not defined for {organization.name} organization")
        return

    if not user.is_member(organization):
        logger.warning(
            f'user with username "{user}" is not member of "{organization.name}"'
        )
        return

    return login_url + get_query_string(user)
