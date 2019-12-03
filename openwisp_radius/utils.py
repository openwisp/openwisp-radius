import swapper
from django3_freeradius.migrations import (DEFAULT_SESSION_TIME_LIMIT, DEFAULT_SESSION_TRAFFIC_LIMIT,
                                          SESSION_TIME_ATTRIBUTE, SESSION_TRAFFIC_ATTRIBUTE)


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
