from openwisp_radius.api.freeradius_views import AccountingView as BaseAccountingView
from openwisp_radius.api.freeradius_views import AuthorizeView as BaseAuthorizeView
from openwisp_radius.api.freeradius_views import PostAuthView as BasePostAuthView
from openwisp_radius.api.views import BatchView as BaseBatchView
from openwisp_radius.api.views import ChangePhoneNumberView as BaseChangePhoneNumberView
from openwisp_radius.api.views import CreatePhoneTokenView as BaseCreatePhoneTokenView
from openwisp_radius.api.views import (
    DownloadRadiusBatchPdfView as BaseDownloadRadiusBatchPdfView,
)
from openwisp_radius.api.views import ObtainAuthTokenView as BaseObtainAuthTokenView
from openwisp_radius.api.views import PasswordChangeView as BasePasswordChangeView
from openwisp_radius.api.views import (
    PasswordResetConfirmView as BasePasswordResetConfirmView,
)
from openwisp_radius.api.views import PasswordResetView as BasePasswordResetView
from openwisp_radius.api.views import RegisterView as BaseRegisterView
from openwisp_radius.api.views import UserAccountingView as BaseUserAccountingView
from openwisp_radius.api.views import ValidateAuthTokenView as BaseValidateAuthTokenView
from openwisp_radius.api.views import (
    ValidatePhoneTokenView as BaseValidatePhoneTokenView,
)


class AuthorizeView(BaseAuthorizeView):
    pass


class PostAuthView(BasePostAuthView):
    pass


class AccountingView(BaseAccountingView):
    pass


class BatchView(BaseBatchView):
    pass


class RegisterView(BaseRegisterView):
    pass


class ObtainAuthTokenView(BaseObtainAuthTokenView):
    pass


class ValidateAuthTokenView(BaseValidateAuthTokenView):
    pass


class UserAccountingView(BaseUserAccountingView):
    pass


class PasswordChangeView(BasePasswordChangeView):
    pass


class PasswordResetView(BasePasswordResetView):
    pass


class PasswordResetConfirmView(BasePasswordResetConfirmView):
    pass


class CreatePhoneTokenView(BaseCreatePhoneTokenView):
    pass


class ValidatePhoneTokenView(BaseValidatePhoneTokenView):
    pass


class ChangePhoneNumberView(BaseChangePhoneNumberView):
    pass


class DownloadRadiusBatchPdfView(BaseDownloadRadiusBatchPdfView):
    pass


authorize = AuthorizeView.as_view()
postauth = PostAuthView.as_view()
accounting = AccountingView.as_view()
batch = BatchView.as_view()
register = RegisterView.as_view()
obtain_auth_token = ObtainAuthTokenView.as_view()
validate_auth_token = ValidateAuthTokenView.as_view()
user_accounting = UserAccountingView.as_view()
password_change = PasswordChangeView.as_view()
password_reset = PasswordResetView.as_view()
password_reset_confirm = PasswordResetConfirmView.as_view()
create_phone_token = CreatePhoneTokenView.as_view()
validate_phone_token = ValidatePhoneTokenView.as_view()
change_phone_number = ChangePhoneNumberView.as_view()
download_rad_batch_pdf = DownloadRadiusBatchPdfView.as_view()
