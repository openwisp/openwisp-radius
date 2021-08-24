from ipaddress import IPv6Network, ip_network

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


def ipv6_network_validator(value):
    try:
        network = ip_network(value)
    except Exception as error:
        raise ValidationError(_('Invalid ipv6 prefix: {error}').format(error=error))
    if not isinstance(network, IPv6Network):
        raise ValidationError(_('{value} is not an IPv6 prefix').format(value=value))
