import logging

from django.utils.translation import gettext_lazy as _
from ipware import get_client_ip
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from ..utils import get_organization_radius_settings, load_model

logger = logging.getLogger(__name__)

OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')


class IsSmsVerificationEnabled(BasePermission):
    def has_permission(self, request, view):
        organization = getattr(view, 'organization')
        client_ip = get_client_ip(request)[0]
        verification = get_organization_radius_settings(
            organization, 'sms_verification'
        )
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
        return get_organization_radius_settings(
            view.organization, 'registration_enabled'
        )
