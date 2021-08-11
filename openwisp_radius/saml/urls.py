from django.urls import path

from . import views


def get_saml_urls(saml_views=None):
    if not saml_views:
        saml_views = views
    return [
        path('login/', views.LoginView.as_view(), name='saml2_login'),
        path('acs/', views.AssertionConsumerServiceView.as_view(), name='saml2_acs'),
        path('logout/', views.LogoutInitView.as_view(), name='saml2_logout'),
        path('ls/', views.LogoutView.as_view(), name='saml2_ls'),
        path('ls/post/', views.LogoutView.as_view(), name='saml2_ls_post'),
        path('metadata/', views.MetadataView.as_view(), name='saml2_metadata'),
    ]
