from ipaddress import IPv6Network, ip_network

import phonenumbers
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.utils.translation import gettext_lazy as _
from phonenumbers import PhoneNumberType, phonenumberutil

URL_VALIDATOR = URLValidator()


def is_mobile_prefix_allowed(phone_number, mobile_prefixes):
    # Let other field validators raise for missing values.
    if not phone_number:
        return True
    country_code = phonenumbers.parse(str(phone_number)).country_code
    return not mobile_prefixes or f"+{country_code}" in mobile_prefixes


def is_mobile_phone_number(phone_number, allow_fixed_line_or_mobile=False):
    # Let other field validators raise for missing values.
    if not phone_number:
        return True
    allowed_types = [PhoneNumberType.MOBILE]
    if allow_fixed_line_or_mobile:
        allowed_types.append(PhoneNumberType.FIXED_LINE_OR_MOBILE)
    return phonenumberutil.number_type(phone_number) in allowed_types


def ipv6_network_validator(value):
    try:
        network = ip_network(value)
    except Exception as error:
        raise ValidationError(_("Invalid ipv6 prefix: {error}").format(error=error))
    if not isinstance(network, IPv6Network):
        raise ValidationError(_("{value} is not an IPv6 prefix").format(value=value))


def password_reset_url_validator(value):
    """
    Substitutes the site placeholder before running URL
    validation on the value.
    """
    from django.contrib.sites.models import Site

    site = Site.objects.get_current()
    value = value.replace("{site}", site.domain)
    URL_VALIDATOR(value)
