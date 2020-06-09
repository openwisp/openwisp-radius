import csv
import os
from datetime import timedelta
from io import StringIO

import swapper
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files import File
from django.core.validators import validate_email
from django.template.loader import get_template
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.translation import ugettext_lazy as _
from sendsms.message import SmsMessage as BaseSmsMessage
from sendsms.signals import sms_post_send
from weasyprint import HTML

from . import settings as app_settings

SESSION_TIME_ATTRIBUTE = 'Max-Daily-Session'
SESSION_TRAFFIC_ATTRIBUTE = 'Max-Daily-Session-Traffic'
DEFAULT_SESSION_TIME_LIMIT = '10800'  # seconds
DEFAULT_SESSION_TRAFFIC_LIMIT = '3000000000'  # bytes (octets)


def load_model(model):
    return swapper.load_model('openwisp_radius', model)


def create_default_groups(organization):
    RadiusGroup = load_model('RadiusGroup')
    RadiusGroupCheck = load_model('RadiusGroupCheck')
    default = RadiusGroup(
        organization_id=organization.pk,
        name='{}-users'.format(organization.slug),
        description='Regular users',
        default=True,
    )
    default.save()
    check = RadiusGroupCheck(
        group_id=default.id,
        groupname=default.name,
        attribute=SESSION_TIME_ATTRIBUTE,
        op=':=',
        value=DEFAULT_SESSION_TIME_LIMIT,
    )
    check.save()
    check = RadiusGroupCheck(
        group_id=default.id,
        groupname=default.name,
        attribute=SESSION_TRAFFIC_ATTRIBUTE,
        op=':=',
        value=DEFAULT_SESSION_TRAFFIC_LIMIT,
    )
    check.save()
    power_users = RadiusGroup(
        organization_id=organization.pk,
        name='{}-power-users'.format(organization.slug),
        description='Users with less restrictions',
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
    hash_.update(settings.SECRET_KEY.encode('utf-8'))
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
        if meta_data and getattr(backend_instance, 'supports_meta_data', False):
            args.append(meta_data)
        res = backend_instance.send_messages(*args)
        sms_post_send.send(
            sender=self, to=self.to, from_phone=self.from_phone, body=self.body
        )
        return res


def find_available_username(username, users_list, prefix=False):
    User = get_user_model()
    suffix = 1
    tmp = '{}{}'.format(username, suffix) if prefix else username
    names_list = map(lambda x: x.username, users_list)
    while User.objects.filter(username=tmp).exists() or tmp in names_list:
        suffix += 1 if prefix else 0
        tmp = '{}{}'.format(username, suffix)
        suffix += 1 if not prefix else 0
    return tmp


def validate_csvfile(csvfile):
    csv_data = csvfile.read()
    try:
        csv_data = csv_data.decode('utf-8') if isinstance(csv_data, bytes) else csv_data
    except UnicodeDecodeError:
        raise ValidationError(
            _(
                'Unrecognized file format, the supplied file '
                'does not look like a CSV file.'
            )
        )
    reader = csv.reader(StringIO(csv_data), delimiter=',')
    error_message = 'The CSV contains a line with invalid data,\
                    line number {} triggered the following error: {}'
    row_count = 1
    for row in reader:
        if len(row) == 5:
            username, password, email, firstname, lastname = row
            try:
                validate_email(email)
            except ValidationError as e:
                raise ValidationError(
                    _(error_message.format(str(row_count), e.message))
                )
            row_count += 1
        elif len(row) > 0:
            raise ValidationError(
                _(error_message.format(str(row_count), 'Improper CSV format.'))
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


def generate_pdf(prefix, data):
    template = get_template(app_settings.BATCH_PDF_TEMPLATE)
    html = HTML(string=template.render(data))
    f = open(f'/tmp/{prefix}.pdf', 'w+b')
    html.write_pdf(target=f)
    f.seek(0)
    return File(f)


def update_user_related_records(sender, instance, created, **kwargs):
    if created:
        return
    instance.radiususergroup_set.update(username=instance.username)
    instance.radiuscheck_set.update(username=instance.username)
    instance.radiusreply_set.update(username=instance.username)
