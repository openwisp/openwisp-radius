from django.urls import include, path

from .api.urls import get_api_urls
from .private_storage.urls import get_private_store_urls
from .saml.urls import get_saml_urls
from .social.urls import get_social_urls


def get_urls(api_views=None, social_views=None, saml_views=None):
    """
    Returns a list of urlpatterns
    Arguements:
        api_views(optional): views for Radius API
        social_view(optional): views for social login (if enabled)
        saml_views(optional): views for saml login (if enabled)
    """
    return [
        path('api/v1/', include(get_api_urls(api_views))),
        path('api/v1/', include(get_private_store_urls())),
        path('radius/social-login/', include(get_social_urls(social_views))),
        path('radius/saml2/', include(get_saml_urls(saml_views))),
    ]


# Cannot used 'app_name' here because when the radius
# urls are not registered, yet we want to get url reverse
# using urlconf we still want radius to be our namespace.
namespace = 'radius'
urlpatterns = [path('', include((get_urls(), namespace), namespace=namespace))]
