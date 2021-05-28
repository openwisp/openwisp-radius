import os

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import include, path

from openwisp_radius.urls import get_urls

from . import views

if os.environ.get('SAMPLE_APP', False):
    # If you are extending the API views or social views,
    # please import them, otherwise pass `None` in place
    # of these values
    from .sample_radius.api import views as api_views
    from .sample_radius.saml import views as saml_views
    from .sample_radius.social import views as social_views

    radius_urls = path(
        '', include((get_urls(api_views, social_views, saml_views), 'radius'))
    )
else:
    api_views = None
    social_views = None
    saml_views = None
    radius_urls = path('', include('openwisp_radius.urls'))

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/', include('openwisp_utils.api.urls')),
    path('api/v1/', include('openwisp_users.api.urls')),
    path('accounts/', include('openwisp_users.accounts.urls')),
    radius_urls,
    path(
        'captive-portal-mock/login/',
        views.captive_portal_login,
        name='captive_portal_login_mock',
    ),
    path(
        'captive-portal-mock/logout/',
        views.captive_portal_logout,
        name='captive_portal_logout_mock',
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

urlpatterns += staticfiles_urlpatterns()
