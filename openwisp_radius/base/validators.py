from ipaddress import IPv6Network, ip_network

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.utils.translation import gettext_lazy as _

URL_VALIDATOR = URLValidator()


def ipv6_network_validator(value):
    try:
        network = ip_network(value)
    except Exception as error:
        raise ValidationError(_('Invalid ipv6 prefix: {error}').format(error=error))
    if not isinstance(network, IPv6Network):
        raise ValidationError(_('{value} is not an IPv6 prefix').format(value=value))


def password_reset_url_validator(value):
    """
    Substitutes the site placeholder before running URL
    validation on the value.
    """
    from django.contrib.sites.models import Site

    site = Site.objects.get_current()
    value = value.replace('{site}', site.domain)
    URL_VALIDATOR(value)
