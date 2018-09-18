from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django_freeradius.api.views import AccountingView as BaseAccountingView
from django_freeradius.api.views import AuthorizeView as BaseAuthorizeView
from django_freeradius.api.views import BatchView as BaseBatchView
from django_freeradius.api.views import PostAuthView as BasePostAuthView
from django_freeradius.api.views import TokenAuthentication as BaseTokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

from openwisp_users.models import Organization

from ..models import OrganizationRadiusSettings


class TokenAuthentication(BaseTokenAuthentication):
    def authenticate(self, request):
        uuid = None
        token = None
        if request.META.get('HTTP_AUTHORIZATION'):
            headers = request.META.get('HTTP_AUTHORIZATION').split(',')
            for header in headers:
                try:
                    uuid = header.split(' ')[1]
                    token = header.split(' ')[2]
                except IndexError:
                    raise AuthenticationFailed('Token authentication failed')
        elif request.GET.get('token') and request.GET.get('uuid'):
            uuid = request.GET.get('uuid')
            token = request.GET.get('token')

        if not uuid or not token:
            raise AuthenticationFailed('Token authentication failed')

        if cache.get(uuid) == token:
            pass
        else:
            try:
                instance = OrganizationRadiusSettings.objects.get(organization=uuid,
                                                                  token=token)
                cache.set(instance.pk, instance.token)
            except OrganizationRadiusSettings.DoesNotExist:
                raise AuthenticationFailed('Token authentication failed')
        return (AnonymousUser(), None)


class TokenAuthorizationMixin(object):
    authentication_classes = (TokenAuthentication,)


class BatchView(BaseBatchView):
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
