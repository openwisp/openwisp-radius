import swapper
from django_freeradius.migrations import (DEFAULT_SESSION_TIME_LIMIT, DEFAULT_SESSION_TRAFFIC_LIMIT,
                                          SESSION_TIME_ATTRIBUTE, SESSION_TRAFFIC_ATTRIBUTE)


def create_default_groups(organization):
    RadiusGroup = swapper.load_model('django_freeradius', 'RadiusGroup')
    RadiusGroupCheck = swapper.load_model('django_freeradius', 'RadiusGroupCheck')
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
