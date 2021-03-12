from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _

IDENTITY_VERIFICATION_CHOICES = [
    (None, _('No Identity Verification')),
    ('mobile', _('Mobile Phone')),
]


def register_verification_choice(name, *args, **kwargs):
    verbose_name = kwargs.get('verbose_name', name)
    IDENTITY_VERIFICATION_CHOICES.append((name, _(verbose_name)))


def unregister_verification_choice(name):
    for index, (key, value) in enumerate(IDENTITY_VERIFICATION_CHOICES):
        if key == name:
            IDENTITY_VERIFICATION_CHOICES.pop(index)
            return
    raise ImproperlyConfigured(f'No such Identity Verification Method "{name}"')
