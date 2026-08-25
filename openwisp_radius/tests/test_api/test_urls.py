from types import SimpleNamespace

from django.test import SimpleTestCase

from ...api import views
from ...api.urls import get_api_urls


class TestApiUrls(SimpleTestCase):
    def test_get_api_urls_uses_overrides_and_default_fallbacks(self):
        def custom_view(request):
            return None

        view_names = {
            "authorize": "authorize",
            "postauth": "postauth",
            "accounting": "accounting",
            "rest_register": "register",
            "rest_password_reset_confirm": "password_reset_confirm",
            "rest_password_reset": "password_reset",
            "rest_password_change": "password_change",
            "user_auth_token": "obtain_auth_token",
            "validate_auth_token": "validate_auth_token",
            "user_accounting": "user_accounting",
            "user_radius_usage": "user_radius_usage",
            "phone_token_create": "create_phone_token",
            "phone_token_status": "get_phone_token_status",
            "phone_token_validate": "validate_phone_token",
            "phone_number_change": "change_phone_number",
            "update_registered_user_registration_method": (
                "update_registered_user_registration_method"
            ),
            "batch": "batch",
            "download_rad_batch_pdf": "download_rad_batch_pdf",
            "radius_accounting_list": "radius_accounting",
            "radius_group_list": "radius_group_list",
            "radius_group_detail": "radius_group_detail",
            "radius_user_group_list": "radius_user_group_list",
            "radius_user_group_detail": "radius_user_group_detail",
        }
        custom_views = SimpleNamespace(
            **{
                view_name: custom_view
                for view_name in view_names.values()
                if view_name != "radius_accounting"
            }
        )
        callbacks = {
            pattern.name: pattern.callback for pattern in get_api_urls(custom_views)
        }

        for url_name, view_name in view_names.items():
            with self.subTest(url_name=url_name):
                expected = (
                    views.radius_accounting
                    if view_name == "radius_accounting"
                    else custom_view
                )
                self.assertIs(callbacks[url_name], expected)
