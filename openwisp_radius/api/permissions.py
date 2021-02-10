import logging

from django.utils.translation import gettext_lazy as _
from ipware import get_client_ip
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from .. import settings as app_settings
from ..utils import load_model
from .utils import is_sms_verification_enabled

logger = logging.getLogger(__name__)

OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')


class IsSmsVerificationEnabled(BasePermission):
    def has_permission(self, request, view):
        organization = getattr(view, 'organization')
        client_ip = get_client_ip(request)[0]
        verification = is_sms_verification_enabled(organization)
        if not verification:
            logger.warning(
                f'View {view.__class__.__name__} is being accessed for organization '
                f'{organization.name} but SMS verification is disabled for '
                f'this organization. Client IP address: {client_ip}'
            )
            raise PermissionDenied(
                _('SMS verification is not enabled for this organization')
            )
        return verification


class IsRegistrationEnabled(BasePermission):
    def has_permission(self, request, view):
        # check for organization's local setting
        try:
            registration_enabled = (
                view.organization.radius_settings.registration_enabled
            )
        except OrganizationRadiusSettings.DoesNotExist:
            registration_enabled = None
        # check for global setting if organization setting not set / doesn't exist
        if registration_enabled is None:
            registration_enabled = app_settings.REGISTRATION_API_ENABLED
        return registration_enabled
