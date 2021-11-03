from django.urls import path

from .. import settings as app_settings


def get_saml_urls(saml_views=None):
    url_patterns = []
    if app_settings.SAML_LOGIN_ENABLED:
        if not saml_views:
            # Need to import views inside the function because SAML
            # is an optional setup and dependencies might not be
            # installed on all systems.
            from . import views

            saml_views = views

        url_patterns = [
            path(
                'login/',
                saml_views.LoginView.as_view(),
                name='saml2_login',
            ),
            path(
                'acs/',
                saml_views.AssertionConsumerServiceView.as_view(),
                name='saml2_acs',
            ),
            path(
                'logout/',
                saml_views.LogoutInitView.as_view(),
                name='saml2_logout',
            ),
            path('ls/', saml_views.LogoutView.as_view(), name='saml2_ls'),
            path(
                'ls/post/',
                saml_views.LogoutView.as_view(),
                name='saml2_ls_post',
            ),
            path(
                'metadata/',
                saml_views.MetadataView.as_view(),
                name='saml2_metadata',
            ),
        ]
    return url_patterns
