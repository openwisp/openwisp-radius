from django.conf.urls import include, url
from django_freeradius import settings as app_settings

from .api import urls as api

app_name = 'freeradius'
urlpatterns = [
    url(r'api/v1/', include(api)),
]

if app_settings.SOCIAL_LOGIN_ENABLED:
    from .social.views import redirect_cp

    urlpatterns.append(
        url(r'^freeradius/social-login/(?P<slug>[\w-]+)/$',
            redirect_cp,
            name='redirect_cp')
    )
