import logging
from uuid import UUID

from allauth.account import app_settings as allauth_settings
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from django.http import Http404
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django_freeradius.api.views import AccountingView as BaseAccountingView
from django_freeradius.api.views import AuthorizeView as BaseAuthorizeView
from django_freeradius.api.views import BatchView as BaseBatchView
from django_freeradius.api.views import ObtainAuthTokenView as BaseObtainAuthTokenView
from django_freeradius.api.views import PostAuthView as BasePostAuthView
from django_freeradius.api.views import ValidateAuthTokenView as BaseValidateAuthTokenView
from rest_auth import app_settings as rest_auth_settings
from rest_auth.app_settings import JWTSerializer, TokenSerializer
from rest_auth.registration.views import RegisterView as BaseRegisterView
from rest_auth.views import PasswordChangeView as BasePasswordChangeView
from rest_auth.views import PasswordResetConfirmView as BasePasswordResetConfirmView
from rest_auth.views import PasswordResetView as BasePasswordResetView
from rest_framework.authentication import BaseAuthentication
from rest_framework.authentication import TokenAuthentication as BaseTokenAuthentication
from rest_framework.exceptions import AuthenticationFailed, ParseError, ValidationError
from rest_framework.serializers import Serializer

from openwisp_users.models import Organization, OrganizationUser

from .. import settings as app_settings
from ..models import OrganizationRadiusSettings

logger = logging.getLogger(__name__)
_TOKEN_AUTH_FAILED = _('Token authentication failed')
User = get_user_model()


class TokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        self.check_organization(request)
        uuid, token = self.get_uuid_token(request)
        if not uuid or not token:
            raise AuthenticationFailed(_TOKEN_AUTH_FAILED)
        # check cache too
        if not cache.get('uuid'):
            try:
                opts = dict(organization_id=uuid, token=token)
                instance = OrganizationRadiusSettings.objects.get(**opts)
                cache.set(uuid, instance.token)
            except OrganizationRadiusSettings.DoesNotExist:
                raise AuthenticationFailed(_TOKEN_AUTH_FAILED)
        elif cache.get(uuid) != token:
            raise AuthenticationFailed(_TOKEN_AUTH_FAILED)
        # if execution gets here the auth token is good
        # we include the organization id in the auth info
        return (AnonymousUser(), uuid)

    def check_organization(self, request):
        if 'organization' in request.data:
            raise AuthenticationFailed(_('setting the organization parameter '
                                         'explicitly is not allowed'))

    def get_uuid_token(self, request):
        # default to GET params
        uuid = request.GET.get('uuid')
        token = request.GET.get('token')
        # inspect authorization header
        if 'HTTP_AUTHORIZATION' in request.META:
            parts = request.META['HTTP_AUTHORIZATION'].split(' ')
            try:
                uuid = parts[1]
                token = parts[2]
            except IndexError:
                raise ParseError('Invalid token')
        return uuid, token


class TokenAuthorizationMixin(object):
    authentication_classes = (TokenAuthentication,)

    def get_serializer(self, *args, **kwargs):
        # supply organization uuid got from authentication
        if 'data' in kwargs:
            # request.data is immutable so we'll use a normal dict
            data = kwargs['data'].copy()
            data['organization'] = self.request.auth
            kwargs['data'] = data
        return super().get_serializer(*args, **kwargs)


class AuthorizeView(TokenAuthorizationMixin, BaseAuthorizeView):
    def get_user(self, request):
        user = super().get_user(request)
        # ensure user is member of the authenticated org
        if user and not OrganizationUser.objects.filter(
            user=user,
            organization_id=request.auth
        ).exists():
            return None
        return user

    def get_serializer(self, *args, **kwargs):
        # needed to avoid `'super' object has no attribute 'get_serializer'`
        # exception, raised in TokenAuthorizationMixin.get_serializer
        return Serializer(*args, **kwargs)


authorize = AuthorizeView.as_view()


class PostAuthView(TokenAuthorizationMixin, BasePostAuthView):
    pass


postauth = PostAuthView.as_view()


class AccountingView(TokenAuthorizationMixin, BaseAccountingView):
    def get_queryset(self):
        return super().get_queryset().filter(organization=self.request.auth)


accounting = AccountingView.as_view()


class BatchView(TokenAuthorizationMixin, BaseBatchView):
    def _create_batch(self, serializer, **kwargs):
        org = Organization.objects.get(pk=self.request.auth)
        options = dict(organization=org)
        options.update(kwargs)
        return super(BatchView, self)._create_batch(serializer, **options)


batch = BatchView.as_view()


class DispatchOrgMixin(object):
    def dispatch(self, *args, **kwargs):
        try:
            self.organization = Organization.objects.get(slug=kwargs['slug'])
        except Organization.DoesNotExist:
            raise Http404()
        return super().dispatch(*args, **kwargs)

    def validate_membership(self, user):
        if (self.organization.pk,) not in user.organizations_pk:
            message = _('User "{}" is not member '
                        'of "{}"').format(user.username, self.organization.slug)
            logger.warning(message)
            raise ValidationError({'non_field_errors': [message]})


class RegisterView(DispatchOrgMixin, BaseRegisterView):
    def perform_create(self, serializer):
        user = super().perform_create(serializer)
        self.organization.add_user(user)
        return user

    def get_response_data(self, user):
        if allauth_settings.EMAIL_VERIFICATION == \
                allauth_settings.EmailVerificationMethod.MANDATORY:
            return {"detail": _("Verification e-mail sent.")}

        context = self.get_serializer_context()

        if getattr(settings, 'REST_USE_JWT', False):
            data = {
                'user': user,
                'token': self.token
            }
            return JWTSerializer(data, context=context).data
        else:
            return TokenSerializer(user.auth_token, context=context).data


register = RegisterView.as_view()


class ObtainAuthTokenView(DispatchOrgMixin, BaseObtainAuthTokenView):
    serializer_class = rest_auth_settings.TokenSerializer

    def get_user(self, serializer, *args, **kwargs):
        user = serializer.validated_data['user']
        self.validate_membership(user)
        return user


obtain_auth_token = csrf_exempt(ObtainAuthTokenView.as_view())


class ValidateAuthTokenView(DispatchOrgMixin, BaseValidateAuthTokenView):
    pass


validate_auth_token = (ValidateAuthTokenView.as_view())


class PasswordChangeView(DispatchOrgMixin, BasePasswordChangeView):
    authentication_classes = (BaseTokenAuthentication,)

    def post(self, request, *args, **kwargs):
        self.validate_membership(request.user)
        return super().post(request, *args, **kwargs)


password_change = PasswordChangeView.as_view()


class PasswordResetView(DispatchOrgMixin, BasePasswordResetView):
    def get_serializer_context(self):
        user = self.get_user()
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        # until django 2.1 urlsafe_base64_encode returned a bytestring
        if not isinstance(uid, str):  # noqa
            uid = uid.decode()
        token = default_token_generator.make_token(user)
        password_reset_urls = app_settings.PASSWORD_RESET_URLS
        default_url = password_reset_urls.get('default')
        password_reset_url = password_reset_urls.get(str(self.organization.pk),
                                                     default_url)
        password_reset_url = password_reset_url.format(
            organization=self.organization.slug,
            uid=uid,
            token=token
        )
        context = {
            'request': self.request,
            'password_reset_url': password_reset_url
        }
        return context

    def get_user(self, *args, **kwargs):
        if self.request.POST.get('email', None):
            email = self.request.POST['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise Http404()
            self.validate_membership(user)
            return user
        raise ParseError('email field is required')


password_reset = PasswordResetView.as_view()


class PasswordResetConfirmView(DispatchOrgMixin, BasePasswordResetConfirmView):
    def post(self, request, *args, **kwargs):
        self.validate_user()
        return super().post(request, *args, **kwargs)

    def validate_user(self, *args, **kwargs):
        if self.request.POST.get('uid', None):
            try:
                uid = force_text(urlsafe_base64_decode(self.request.POST['uid']))
                uid = UUID(str(uid))
                user = User.objects.get(pk=uid)
            except (User.DoesNotExist, ValueError):
                raise Http404()
            self.validate_membership(user)
            return user


password_reset_confirm = PasswordResetConfirmView.as_view()
