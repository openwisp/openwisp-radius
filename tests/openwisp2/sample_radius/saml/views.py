from openwisp_radius.saml.views import (
    AssertionConsumerServiceView as BaseAssertionConsumerServiceView,
)
from openwisp_radius.saml.views import LoginView as BaseLoginView
from openwisp_radius.saml.views import LogoutInitView as BaseLogoutInitView
from openwisp_radius.saml.views import LogoutView as BaseLogoutView
from openwisp_radius.saml.views import MetadataView as BaseMetadataView


class AssertionConsumerServiceView(BaseAssertionConsumerServiceView):
    pass


class LoginView(BaseLoginView):
    pass


class LogoutInitView(BaseLogoutInitView):
    pass


class LogoutView(BaseLogoutView):
    pass


class MetadataView(BaseMetadataView):
    pass
