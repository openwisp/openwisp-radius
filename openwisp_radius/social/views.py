from django.core.exceptions import SuspiciousOperation
from django.http import Http404
from django_freeradius.social.views import RedirectCaptivePageView as BaseRedirectCaptivePageView

from openwisp_users.models import Organization


class RedirectCaptivePageView(BaseRedirectCaptivePageView):
    def authorize(self, request, *args, **kwargs):
        """
        subscribes user to organization
        """
        super().authorize(request)
        user = request.user
        slug = kwargs.get('slug')
        try:
            org = Organization.objects.get(slug=slug)
        except Organization.DoesNotExist:
            raise Http404()
        is_member = (org.pk,) in user.organizations_pk
        # to avoid this, we should fix this:
        # https://github.com/openwisp/openwisp-users/issues/34
        if user.is_staff and not is_member:
            raise SuspiciousOperation()
        # add user to organization
        if not is_member:
            org.add_user(user)


redirect_cp = RedirectCaptivePageView.as_view()
