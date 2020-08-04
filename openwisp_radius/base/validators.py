from ipaddress import IPv6Network, ip_network

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def ipv6_network_validator(value):
    try:
        network = ip_network(value)
    except Exception as error:
        raise ValidationError(_(f'Invalid ipv6 prefix: {error}'))
    if not isinstance(network, IPv6Network):
        raise ValidationError(_(f'{value} is not an IPv6 prefix'))
