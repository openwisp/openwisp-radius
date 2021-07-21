from django.urls import path

from . import views


def get_saml_urls(saml_views=None):
    if not saml_views:
        saml_views = views
    url_patterns = []
    if saml_views.SAML_LOGIN_ENABLED:
        url_patterns = [
            path('login/', saml_views.LoginView.as_view(), name='saml2_login'),
            path(
                'acs/',
                saml_views.AssertionConsumerServiceView.as_view(),
                name='saml2_acs',
            ),
            path('logout/', saml_views.LogoutInitView.as_view(), name='saml2_logout'),
            path('ls/', saml_views.LogoutView.as_view(), name='saml2_ls'),
            path('ls/post/', saml_views.LogoutView.as_view(), name='saml2_ls_post'),
            path('metadata/', saml_views.MetadataView.as_view(), name='saml2_metadata'),
        ]
    return (url_patterns, 'radius_saml')
