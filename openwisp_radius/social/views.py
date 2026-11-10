import swapper
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.utils.translation import gettext_lazy as _
from django.views import View

from openwisp_users.auth import create_auth_token, is_password_based_user

from ..api.views import RadiusTokenMixin
from ..utils import get_organization_radius_settings, load_model

Organization = swapper.load_model("openwisp_users", "Organization")
RadiusToken = load_model("RadiusToken")
RegisteredUser = load_model("RegisteredUser")
OrganizationUser = swapper.load_model("openwisp_users", "OrganizationUser")


class RedirectCaptivePageView(RadiusTokenMixin, View):
    def get(self, request, *args, **kwargs):
        """
        redirect user to captive page
        with the social auth token in the querystring
        (which will allow the captive page to send the token to freeradius)
        """
        if not request.GET.get("cp"):
            return HttpResponse(_("missing cp GET param"), status=400)
        org = get_object_or_404(Organization, slug=kwargs.get("slug"))
        if not org.is_active:
            raise PermissionDenied
        self.authorize(request, org, *args, **kwargs)
        return HttpResponseRedirect(self.get_redirect_url(request, org))

    def authorize(self, request, org, *args, **kwargs):
        """
        authorization logic
        raises PermissionDenied if user is not authorized
        """
        if not get_organization_radius_settings(org, "social_registration_enabled"):
            raise PermissionDenied

        user = request.user
        if not user.is_authenticated or not user.socialaccount_set.exists():
            raise PermissionDenied()
        user = request.user
        is_member = user.is_member(org)
        # add user to organization
        with transaction.atomic():
            if not is_member:
                orgUser = OrganizationUser(organization=org, user=user)
                orgUser.full_clean()
                orgUser.save()
            registered_user, created = RegisteredUser.get_or_create_for_user_and_org(
                user=user,
                organization=org,
                defaults={"method": "social_login", "is_verified": False},
            )
            if not created:
                if registered_user.method == "pending_verification":
                    registered_user.method = "social_login"
                    registered_user.is_verified = False
                    registered_user.full_clean()
                    registered_user.save()

    def get_redirect_url(self, request, organization):
        """
        refreshes token and returns the captive page URL
        """
        cp = request.GET.get("cp")
        user = request.user
        token = create_auth_token(request, user, renew=True)
        rad_token = self.get_or_create_radius_token(
            user, organization, password_based=is_password_based_user(user)
        )
        return (
            f"{cp}?username={user.username}&token={token.key}&"
            f"radius_user_token={rad_token.key}"
        )


redirect_cp = RedirectCaptivePageView.as_view()
