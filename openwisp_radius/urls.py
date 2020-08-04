from django.urls import include, path

from . import settings as app_settings
from .api.urls import get_api_urls
from .private_storage.views import rad_batch_csv_download_view


def get_urls(api_views=None, social_views=None):
    """
    Returns a list of urlpatterns
    Arguements:
        api_views(optional): views for Radius API
        social_view(optional): views for social login (if enabled)
    """
    if not social_views:
        from .social import views as social_views
    urls = [
        path('api/v1/', include(get_api_urls(api_views))),
        path(
            'radiusbatch/csv/<path:csvfile>',
            rad_batch_csv_download_view,
            name='serve_private_file',
        ),
    ]
    if app_settings.SOCIAL_LOGIN_ENABLED:
        urls.append(
            path(
                'radius/social-login/<slug:slug>/',
                social_views.redirect_cp,
                name='redirect_cp',
            )
        )
    return urls


app_name = 'radius'
urlpatterns = get_urls()
