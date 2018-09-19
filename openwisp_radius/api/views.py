from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.utils.translation import ugettext_lazy as _
from django_freeradius.api.views import AccountingView as BaseAccountingView
from django_freeradius.api.views import AuthorizeView as BaseAuthorizeView
from django_freeradius.api.views import BatchView as BaseBatchView
from django_freeradius.api.views import PostAuthView as BasePostAuthView
from django_freeradius.api.views import TokenAuthentication as BaseTokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

from openwisp_users.models import Organization

from ..models import OrganizationRadiusSettings

_TOKEN_AUTH_FAILED = _('Token authentication failed')


class TokenAuthentication(BaseTokenAuthentication):
    def authenticate(self, request):
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
        return (AnonymousUser(), None)


class TokenAuthorizationMixin(object):
    authentication_classes = (TokenAuthentication,)


class BatchView(TokenAuthorizationMixin, BaseBatchView):
    def _create_batch(self, serializer, **kwargs):
        org_id = serializer.data.get('organization')
        org = Organization.objects.get(pk=org_id)
        options = dict(organization=org)
        options.update(kwargs)
        return super(BatchView, self)._create_batch(serializer, **options)


batch = BatchView.as_view()


class AuthorizeView(TokenAuthorizationMixin, BaseAuthorizeView):
    pass


authorize = AuthorizeView.as_view()


class PostAuthView(TokenAuthorizationMixin, BasePostAuthView):
    pass


postauth = PostAuthView.as_view()


class AccountingView(TokenAuthorizationMixin, BaseAccountingView):
    pass


accounting = AccountingView.as_view()
