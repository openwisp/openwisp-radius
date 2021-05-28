from urllib.parse import parse_qs, urlparse

import swapper
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist
from django.shortcuts import get_object_or_404
from djangosaml2.views import (
    AssertionConsumerServiceView as BaseAssertionConsumerServiceView,
)
from djangosaml2.views import (  # noqa
    LoginView,
    LogoutInitView,
    LogoutView,
    MetadataView,
)
from rest_framework.authtoken.models import Token

from .. import settings as app_settings
from ..api.views import RadiusTokenMixin
from ..utils import load_model
from .utils import get_url_or_path

Organization = swapper.load_model('openwisp_users', 'Organization')
RadiusToken = load_model('RadiusToken')
RegisteredUser = load_model('RegisteredUser')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')


class AssertionConsumerServiceView(RadiusTokenMixin, BaseAssertionConsumerServiceView):
    def get_organization_from_relay_state(self):
        try:
            parsed_url = urlparse(self.request.POST.get('RelayState'), None)
            org_slug = parse_qs(parsed_url.query)['org'][0]
        except (KeyError, IndexError):
            raise ImproperlyConfigured('Organization slug not provided')
        else:
            return get_object_or_404(Organization, slug=org_slug)

    def post_login_hook(self, request, user, session_info):
        """ If desired, a hook to add logic after a user has successfully logged in.
        """
        org = self.get_organization_from_relay_state()
        is_member = user.is_member(org)
        # add user to organization
        if not is_member:
            orgUser = OrganizationUser(organization=org, user=user)
            orgUser.full_clean()
            orgUser.save()
        try:
            user.registered_user
        except ObjectDoesNotExist:
            registered_user = RegisteredUser(
                user=user, method='saml', is_verified=app_settings.SAML_IS_VERIFIED
            )
            registered_user.full_clean()
            registered_user.save()

    def customize_relay_state(self, relay_state):
        """ Subclasses may override this method to implement custom logic for relay state.
        """
        return get_url_or_path(relay_state)

    def custom_redirect(self, user, relay_state, session_info):
        """ Subclasses may override this method to implement custom logic for redirect.

            For example, some sites may require user registration if the user has not
            yet been provisioned.
        """
        organization = self.get_organization_from_relay_state()
        Token.objects.filter(user=user).delete()
        token, _ = Token.objects.get_or_create(user=user)
        rad_token = self.get_or_create_radius_token(user, organization)
        return (
            f'{relay_state}?username={user.username}&token={token.key}&'
            f'radius_user_token={rad_token.key}'
        )
