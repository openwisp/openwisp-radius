from django.urls import path

from .. import settings as app_settings
from . import views


def get_social_urls(social_views=None):
    if not app_settings.SOCIAL_REGISTRATION_CONFIGURED:
        return []

    if not social_views:
        social_views = views

    return [
        path(
            '<slug:slug>/',
            social_views.redirect_cp,
            name='redirect_cp',
        )
    ]
