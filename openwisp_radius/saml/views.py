import logging
from urllib.parse import parse_qs, urlparse

import swapper
from django.conf import settings
from django.contrib.auth import logout
from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import get_object_or_404, render
from djangosaml2.views import (
    AssertionConsumerServiceView as BaseAssertionConsumerServiceView,
)
from djangosaml2.views import LoginView as BaseLoginView
from djangosaml2.views import LogoutInitView, LogoutView, MetadataView  # noqa
from rest_framework.authtoken.models import Token

from .. import settings as app_settings
from ..api.views import RadiusTokenMixin
from ..utils import load_model
from .utils import get_url_or_path

logger = logging.getLogger(__name__)

Organization = swapper.load_model('openwisp_users', 'Organization')
RadiusToken = load_model('RadiusToken')
RegisteredUser = load_model('RegisteredUser')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')


class OrganizationSamlMixin(object):
    def get_org_slug_from_relay_state(self):
        try:
            parsed_url = urlparse(
                self.request.POST.get(
                    'RelayState',
                    self.request.GET.get('RelayState', None),
                )
            )

            org_slug = parse_qs(parsed_url.query)['org'][0]
        except (KeyError, IndexError):
            raise ValueError('Organization slug not provided')
        else:
            return org_slug

    def get_organization_from_relay_state(self):
        org_slug = self.get_org_slug_from_relay_state()
        return get_object_or_404(Organization, slug=org_slug)


class AssertionConsumerServiceView(
    OrganizationSamlMixin, RadiusTokenMixin, BaseAssertionConsumerServiceView
):
    def post_login_hook(self, request, user, session_info):
        """If desired, a hook to add logic after a user has successfully logged in."""
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
        """
        Subclasses may override this method to
        implement custom logic for relay state.
        """
        return get_url_or_path(relay_state)

    def custom_redirect(self, user, relay_state, session_info):
        """Subclasses may override this method to implement custom logic for redirect.

        For example, some sites may require user registration if the user has not
        yet been provisioned.
        """
        Token.objects.filter(user=user).delete()
        token, _ = Token.objects.get_or_create(user=user)
        return (
            f'{relay_state}?username={user.username}&token={token.key}&'
            f'login_method=saml'
        )


class LoginView(OrganizationSamlMixin, BaseLoginView):
    def load_sso_kwargs(self, sso_kwargs):
        service_config = (
            getattr(settings, 'SAML_CONFIG', {}).get('service', {}).get('sp', None)
        )
        sso_kwargs['isPassive'] = service_config.get('isPassive', False)
        sso_kwargs['attribute_consuming_service_index'] = service_config.get(
            'attribute_consuming_service_index', '1'
        )

    def get(self, request, *args, **kwargs):
        # Check correct organization slug is present in the request
        try:
            org_slug = self.get_org_slug_from_relay_state()
            assert Organization.objects.filter(
                slug=org_slug
            ).exists(), 'Organization with the provided slug does not exist'
        except (ValueError, AssertionError) as error:
            logger.error(str(error))
            return render(request, 'djangosaml2/login_error.html')

        # Log out the user before initiating the SAML flow
        # to avoid past sessions to get in the way and break the flow
        if request.user.is_authenticated:
            logout(request)
        return super().get(request, *args, **kwargs)
