import os

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.urls import include, path

from openwisp_radius.urls import get_urls

if os.environ.get('SAMPLE_APP', False):
    # If you are extending the API views or social views,
    # please import them, otherwise pass `None` in place
    # of these values
    from .sample_radius.api import views as api_views
    from .sample_radius.social import views as social_views
else:
    api_views = None
    social_views = None

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('openwisp_users.accounts.urls')),
    path('', include('openwisp_radius.urls')),
    path(
        '', include((get_urls(api_views, social_views), 'radius'), namespace='radius')
    ),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

urlpatterns += staticfiles_urlpatterns()
