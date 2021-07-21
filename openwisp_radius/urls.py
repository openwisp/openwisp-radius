from django.urls import include, path

from .api.urls import get_api_urls
from .social.urls import get_social_urls
from .saml.urls import get_saml_urls


def get_urls(api_views=None, social_views=None, saml_views=None):
    """
    Returns a list of urlpatterns
    Arguements:
        api_views(optional): views for Radius API
        social_view(optional): views for social login (if enabled)
    """
    urls = [
        path('api/v1/', include(get_api_urls(api_views))),
        path('api/v1/', include(get_social_urls(social_views))),
        path('api/v1/', include('openwisp_radius.private_storage.urls')),
        path('radius/saml2/', include(get_saml_urls(saml_views))),
    ]
    return urls


urlpatterns = get_urls()
