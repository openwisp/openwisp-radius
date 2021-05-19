from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _

IDENTITY_VERIFICATION_CHOICES = [
    (None, _('Email (No Identity Verification)')),
    ('mobile', _('Mobile Phone (SMS)')),
]


def register_identity_verification_method(name, verbose_name):
    IDENTITY_VERIFICATION_CHOICES.append((name, verbose_name))


def unregister_identity_verification_method(name):
    for index, (key, value) in enumerate(IDENTITY_VERIFICATION_CHOICES):
        if key == name:
            IDENTITY_VERIFICATION_CHOICES.pop(index)
            return
    raise ImproperlyConfigured(f'No such Identity Verification Method "{name}"')
