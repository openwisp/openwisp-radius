import swapper
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.utils.translation import ugettext_lazy as _
from django.views import View
from rest_framework.authtoken.models import Token

from ..utils import load_model

Organization = swapper.load_model('openwisp_users', 'Organization')
RadiusToken = load_model('RadiusToken')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')


class RedirectCaptivePageView(View):
    def get(self, request, *args, **kwargs):
        """
        redirect user to captive page
        with the social auth token in the querystring
        (which will allow the captive page to send the token to freeradius)
        """
        if not request.GET.get('cp'):
            return HttpResponse(_('missing cp GET param'), status=400)
        self.authorize(request, *args, **kwargs)
        return HttpResponseRedirect(self.get_redirect_url(request))

    def authorize(self, request, *args, **kwargs):
        """
        authorization logic
        raises PermissionDenied if user is not authorized
        """
        user = request.user
        if not user.is_authenticated or not user.socialaccount_set.exists():
            raise PermissionDenied()
        user = request.user
        slug = kwargs.get('slug')
        try:
            org = Organization.objects.get(slug=slug)
        except Organization.DoesNotExist:
            raise Http404()
        is_member = user.is_member(org)
        # to avoid this, we should fix this:
        # https://github.com/openwisp/openwisp-users/issues/34
        if user.is_staff and not is_member:
            raise SuspiciousOperation()
        # add user to organization
        if not is_member:
            orgUser = OrganizationUser(organization=org, user=user)
            orgUser.full_clean()
            orgUser.save()

    def get_redirect_url(self, request):
        """
        refreshes token and returns the captive page URL
        """
        cp = request.GET.get('cp')
        user = request.user
        Token.objects.filter(user=user).delete()
        RadiusToken.objects.filter(user=user).delete()
        token = Token.objects.create(user=user)
        rad_token = RadiusToken.objects.create(user=user)
        return '{0}?username={1}&token={2}&radius_user_token={3}'.format(
            cp, user.username, token.key, rad_token.key
        )


redirect_cp = RedirectCaptivePageView.as_view()
