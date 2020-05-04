from openwisp_radius.social.views import (
    RedirectCaptivePageView as BaseRedirectCaptivePageView,
)


class RedirectCaptivePageView(BaseRedirectCaptivePageView):
    pass


redirect_cp = RedirectCaptivePageView.as_view()
