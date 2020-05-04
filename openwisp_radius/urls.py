from django.conf.urls import include, url

from . import settings as app_settings
from .api.urls import get_api_urls


def get_urls(api_views=None, social_views=None):
    """
    Returns a list of urlpatterns
    Arguements:
        api_views(optional): views for Radius API
        social_view(optional): views for social login (if enabled)
    """
    if not social_views:
        from .social import views as social_views
    urls = [url(r'api/v1/', include(get_api_urls(api_views)))]
    if app_settings.SOCIAL_LOGIN_ENABLED:
        urls.append(
            url(
                r'^freeradius/social-login/(?P<slug>[\w-]+)/$',
                social_views.redirect_cp,
                name='redirect_cp',
            )
        )
    return urls


app_name = 'radius'
urlpatterns = get_urls()
