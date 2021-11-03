from django.urls import path

from .. import settings as app_settings
from . import views


def get_social_urls(social_views=None):
    if not social_views:
        social_views = views
    url_patterns = []
    if app_settings.SOCIAL_LOGIN_ENABLED:
        url_patterns = [
            path(
                '<slug:slug>/',
                social_views.redirect_cp,
                name='redirect_cp',
            )
        ]
    return url_patterns
