from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.utils.translation import ugettext_lazy as _
from django_freeradius.api.views import AccountingView as BaseAccountingView
from django_freeradius.api.views import AuthorizeView as BaseAuthorizeView
from django_freeradius.api.views import BatchView as BaseBatchView
from django_freeradius.api.views import PostAuthView as BasePostAuthView
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from openwisp_users.models import Organization, OrganizationUser

from ..models import OrganizationRadiusSettings

_TOKEN_AUTH_FAILED = _('Token authentication failed')


class TokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        self.check_organization(request)
        uuid, token = self.get_uuid_token(request)
        if not uuid or not token:
            raise AuthenticationFailed(_TOKEN_AUTH_FAILED)
        # check cache too
        if uuid not in cache:
            try:
                opts = dict(organization=uuid, token=token)
                instance = OrganizationRadiusSettings.objects.get(**opts)
                cache.set(instance.pk, instance.token)
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
                pass
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


authorize = AuthorizeView.as_view()


class PostAuthView(TokenAuthorizationMixin, BasePostAuthView):
    pass


postauth = PostAuthView.as_view()


class AccountingView(TokenAuthorizationMixin, BaseAccountingView):
    pass


accounting = AccountingView.as_view()


class BatchView(TokenAuthorizationMixin, BaseBatchView):
    def _create_batch(self, serializer, **kwargs):
        org = Organization.objects.get(pk=self.request.auth)
        options = dict(organization=org)
        options.update(kwargs)
        return super(BatchView, self)._create_batch(serializer, **options)


batch = BatchView.as_view()
