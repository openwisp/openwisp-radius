import os
from datetime import timedelta

import swapper
from django.conf import settings
from django.utils import timezone
from django_freeradius.migrations import (DEFAULT_SESSION_TIME_LIMIT, DEFAULT_SESSION_TRAFFIC_LIMIT,
                                          SESSION_TIME_ATTRIBUTE, SESSION_TRAFFIC_ATTRIBUTE)

from . import settings as app_settings


def load_model(model):
    return swapper.load_model('openwisp_radius', model)


def create_default_groups(organization):
    RadiusGroup = load_model('RadiusGroup')
    RadiusGroupCheck = load_model('RadiusGroupCheck')
    default = RadiusGroup(organization_id=organization.pk,
                          name='{}-users'.format(organization.slug),
                          description='Regular users',
                          default=True)
    default.save()
    check = RadiusGroupCheck(group_id=default.id,
                             groupname=default.name,
                             attribute=SESSION_TIME_ATTRIBUTE,
                             op=':=',
                             value=DEFAULT_SESSION_TIME_LIMIT)
    check.save()
    check = RadiusGroupCheck(group_id=default.id,
                             groupname=default.name,
                             attribute=SESSION_TRAFFIC_ATTRIBUTE,
                             op=':=',
                             value=DEFAULT_SESSION_TRAFFIC_LIMIT)
    check.save()
    power_users = RadiusGroup(organization_id=organization.pk,
                              name='{}-power-users'.format(organization.slug),
                              description='Users with less restrictions',
                              default=False)
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
