import logging
from urllib.parse import parse_qs, quote, urlencode, urlparse

import swapper
from allauth.account.models import EmailAddress
from allauth.account.utils import send_email_confirmation
from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied, ValidationError
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.generic import UpdateView
from djangosaml2.utils import validate_referral_url
from djangosaml2.views import (
    AssertionConsumerServiceView as BaseAssertionConsumerServiceView,
)
from djangosaml2.views import LoginView as BaseLoginView
from djangosaml2.views import LogoutInitView, LogoutView, MetadataView  # noqa
from rest_framework.authtoken.models import Token

from .. import settings as app_settings
from ..api.views import RadiusTokenMixin
from ..utils import get_organization_radius_settings, load_model
from .utils import get_url_or_path

logger = logging.getLogger(__name__)

User = get_user_model()
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
        # In some cases, it possible that the organization cache for
        # the user is not updated before execution of the following
        # code. Hence, the cache is manually updated here.
        user._invalidate_user_organizations_dict()
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
            # The user is just created, it will not have an email address
            if user.email:
                try:
                    email_address = EmailAddress(
                        user=user, email=user.email, primary=True, verified=True
                    )
                    email_address.full_clean()
                    email_address.save()
                except ValidationError:
                    logger.exception(
                        f'Failed email validation for "{user}"'
                        ' during SAML user creation'
                    )

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
        next = '{relay_state}?{params}'.format(
            relay_state=relay_state,
            params=urlencode(
                {'username': user.username, 'token': token.key, 'login_method': 'saml'}
            ),
        )
        return '{path}?next={next}'.format(
            path=reverse('radius:saml2_additional_info'), next=quote(next)
        )


class LoginAdditionalInfoForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['email']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['email'].required = True


class LoginAdditionalInfoView(LoginRequiredMixin, UpdateView):
    model = User
    form_class = LoginAdditionalInfoForm
    template_name = 'djangosaml2/login_additional_info.html'

    def get_object(self):
        return self.request.user

    def get_response(self):
        success_url = self.get_success_url()
        if success_url:
            return redirect(success_url)
        return render(self.request, 'djangosaml2/login_error.html')

    def get_success_url(self):
        return validate_referral_url(self.request, self.request.GET.get('next'))

    def form_valid(self, form):
        user = form.save()
        send_email_confirmation(self.request, user, signup=True, email=user.email)
        return self.get_response()

    def is_user_profile_complete(self):
        return self.request.user.email

    def get(self, request, *args, **kwargs):
        # Redirect user to the next page if the user profile is complete.
        if self.is_user_profile_complete():
            return self.get_response()
        return super().get(request, *args, **kwargs)


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
            organization = Organization.objects.only('id', 'radius_settings').get(
                slug=org_slug
            )
        except (ValueError, ObjectDoesNotExist) as error:
            if isinstance(error, ObjectDoesNotExist):
                logger.error('Organization with the provided slug does not exist')
            else:
                logger.error(str(error))
            return render(request, 'djangosaml2/login_error.html')
        else:
            if not get_organization_radius_settings(
                organization, 'saml_registration_enabled'
            ):
                raise PermissionDenied()

        # Log out the user before initiating the SAML flow
        # to avoid past sessions to get in the way and break the flow
        if request.user.is_authenticated:
            logout(request)
        return super().get(request, *args, **kwargs)
