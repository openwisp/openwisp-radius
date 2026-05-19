import logging

from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import gettext_lazy as _

from . import settings as app_settings
from .utils import load_model

REGISTRATION_METHOD_CHOICES = [
    ("", "Unspecified"),
    ("manual", _("Manually created")),
    ("email", _("Email")),
    ("mobile_phone", _("Mobile phone")),
    ("pending_verification", _("Pending Verification")),
]

AUTHORIZE_UNVERIFIED = []

logger = logging.getLogger(__name__)


def register_registration_method(
    name,
    verbose_name,
    authorize_unverified=False,
    fail_loud=True,
    strong_identity=False,
):
    # check if it's a duplicate
    duplicate = False
    for method_tuple in REGISTRATION_METHOD_CHOICES:
        if method_tuple[0] == name:
            duplicate = True
            break
    # add if not duplicate, fail otherwise, unless fail_on_duplicate=False is passed
    if not duplicate:
        REGISTRATION_METHOD_CHOICES.append((name, verbose_name))
    elif fail_loud:
        raise ImproperlyConfigured(f"Method {name} is already registered")
    else:
        logger.info(f"Method {name} is already registered")
    # needed to implement 3D secure verification
    # when doing credit/debit card payments
    if authorize_unverified and name not in AUTHORIZE_UNVERIFIED:
        AUTHORIZE_UNVERIFIED.append(name)
    if not strong_identity:
        RegisteredUser = load_model("RegisteredUser")
        RegisteredUser._weak_verification_methods.add(name)


def unregister_registration_method(name, fail_loud=True):
    for index, (key, value) in enumerate(REGISTRATION_METHOD_CHOICES):
        if key == name:
            REGISTRATION_METHOD_CHOICES.pop(index)
            return
    # if not found, fail, unless fail_on_duplicate=False is passed
    if fail_loud:
        raise ImproperlyConfigured(f'No such Identity Verification Method "{name}"')


def get_registration_choices():
    return REGISTRATION_METHOD_CHOICES


def validate_user_settable_registration_methods(methods):
    if not isinstance(methods, (list, tuple)):
        raise ImproperlyConfigured(
            "OPENWISP_RADIUS_USER_SETTABLE_REGISTRATION_METHODS must be a list or tuple"
        )
    methods = list(methods)
    duplicates = []
    seen = set()
    for method in methods:
        if method in seen and method not in duplicates:
            duplicates.append(method)
        seen.add(method)
    if duplicates:
        raise ImproperlyConfigured(
            "OPENWISP_RADIUS_USER_SETTABLE_REGISTRATION_METHODS contains duplicate "
            f"values: {', '.join(repr(method) for method in duplicates)}"
        )
    available_choices = dict(get_registration_choices())
    invalid_methods = [method for method in methods if method not in available_choices]
    if invalid_methods:
        raise ImproperlyConfigured(
            "OPENWISP_RADIUS_USER_SETTABLE_REGISTRATION_METHODS contains unknown "
            f"values: {', '.join(repr(method) for method in invalid_methods)}"
        )

    return [(method, available_choices[method]) for method in methods]
