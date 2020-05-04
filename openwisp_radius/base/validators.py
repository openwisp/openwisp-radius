from ipaddress import IPv6Network, ip_network

from django.core.exceptions import ValidationError


def ipv6_network_validator(value):
    try:
        network = ip_network(value)
    except Exception as e:
        raise ValidationError('Invalid ipv6 prefix: {}'.format(e))
    if not isinstance(network, IPv6Network):
        raise ValidationError('{} is not an IPv6 prefix'.format(value))
