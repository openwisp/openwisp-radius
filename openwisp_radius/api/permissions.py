import logging

from django.utils.translation import gettext_lazy as _
from ipware import get_client_ip
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import SAFE_METHODS, BasePermission

from ..utils import get_organization_radius_settings, load_model

logger = logging.getLogger(__name__)

OrganizationRadiusSettings = load_model("OrganizationRadiusSettings")


class BaseOrganizationPermission(BasePermission):
    pass


class IsOrganizationActive(BaseOrganizationPermission):
    # openwisp_users.api.permissions.DisabledOrgReadOnly only implements
    # has_object_permission, so it can't guard views whose organization
    # comes from the URL slug (DispatchOrgMixin) instead of a fetched
    # object, e.g. a write on a view with no object yet. This class fills
    # that view-level gap with has_permission instead.
    message = _(
        "The organization {organization} is currently disabled: only read operations "
        "are allowed."
    )

    def has_permission(self, request, view):
        organization = getattr(view, "organization", None)
        if (
            getattr(view, "allow_disabled_organization_writes", False)
            or organization is None
            or organization.is_active
            or request.method in SAFE_METHODS
        ):
            return True
        self.message = self.message.format(organization=organization.name)
        return False


class IsSmsVerificationEnabled(BaseOrganizationPermission):
    def has_permission(self, request, view):
        organization = getattr(view, "organization")
        client_ip = get_client_ip(request)[0]
        verification = get_organization_radius_settings(
            organization, "sms_verification"
        )
        if not verification:
            logger.warning(
                f"View {view.__class__.__name__} is being accessed for organization "
                f"{organization.name} but SMS verification is disabled for "
                f"this organization. Client IP address: {client_ip}"
            )
            raise PermissionDenied(
                _("SMS verification is not enabled for this organization")
            )
        return verification


class IsRegistrationEnabled(BaseOrganizationPermission):
    def has_permission(self, request, view):
        return get_organization_radius_settings(
            view.organization, "registration_enabled"
        )
