import os

from django.conf import settings
from django.conf.urls import include, url
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

from openwisp_radius.urls import get_urls

from .sample_radius.api import views as api_views
from .sample_radius.social import views as social_views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^accounts/', include('openwisp_users.accounts.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if os.environ.get('SAMPLE_APP', False):
    urlpatterns += [
        url(
            r'^',
            include((get_urls(api_views, social_views), 'radius'), namespace='radius',),
        ),
    ]
else:
    urlpatterns += [
        url(r'^', include('openwisp_radius.urls', namespace='radius')),
    ]

urlpatterns += staticfiles_urlpatterns()
