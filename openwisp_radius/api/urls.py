from django.urls import path

from .. import settings as app_settings
from . import views


def get_api_urls(api_views=None):
    if not api_views:
        api_views = views

    def get_view(name):
        """Fall back to the standard view when a custom view is unavailable."""
        return getattr(api_views, name, getattr(views, name))

    if app_settings.RADIUS_API:
        return [
            path("freeradius/authorize/", get_view("authorize"), name="authorize"),
            path("freeradius/postauth/", get_view("postauth"), name="postauth"),
            path("freeradius/accounting/", get_view("accounting"), name="accounting"),
            # registration differentiated by organization
            path(
                "radius/organization/<slug:slug>/account/",
                get_view("register"),
                name="rest_register",
            ),
            # password reset
            path(
                "radius/organization/<slug:slug>/account/password/reset/confirm/",
                get_view("password_reset_confirm"),
                name="rest_password_reset_confirm",
            ),
            path(
                "radius/organization/<slug:slug>/account/password/reset/",
                get_view("password_reset"),
                name="rest_password_reset",
            ),
            path(
                "radius/organization/<slug:slug>/account/password/change/",
                get_view("password_change"),
                name="rest_password_change",
            ),
            # obtaining the user token is also different for every org
            path(
                "radius/organization/<slug:slug>/account/token/",
                get_view("obtain_auth_token"),
                name="user_auth_token",
            ),
            path(
                "radius/organization/<slug:slug>/account/token/validate/",
                get_view("validate_auth_token"),
                name="validate_auth_token",
            ),
            path(
                "radius/organization/<slug:slug>/account/session/",
                get_view("user_accounting"),
                name="user_accounting",
            ),
            path(
                "radius/organization/<slug:slug>/account/usage/",
                get_view("user_radius_usage"),
                name="user_radius_usage",
            ),
            # generate new sms phone token
            path(
                "radius/organization/<slug:slug>/account/phone/token/",
                get_view("create_phone_token"),
                name="phone_token_create",
            ),
            path(
                "radius/organization/<slug:slug>/account/phone/token/active/",
                get_view("get_phone_token_status"),
                name="phone_token_status",
            ),
            path(
                "radius/organization/<slug:slug>/account/phone/verify/",
                get_view("validate_phone_token"),
                name="phone_token_validate",
            ),
            # allow changing phone number
            path(
                "radius/organization/<slug:slug>/account/phone/change/",
                get_view("change_phone_number"),
                name="phone_number_change",
            ),
            path(
                "radius/organization/<slug:slug>/account/registration-method/",
                get_view("update_registered_user_registration_method"),
                name="update_registered_user_registration_method",
            ),
            path("radius/batch/", get_view("batch"), name="batch"),
            path(
                "radius/organization/<slug:slug>/batch/<uuid:pk>/pdf/",
                get_view("download_rad_batch_pdf"),
                name="download_rad_batch_pdf",
            ),
            path(
                "radius/sessions/",
                get_view("radius_accounting"),
                name="radius_accounting_list",
            ),
            path(
                "radius/group/",
                get_view("radius_group_list"),
                name="radius_group_list",
            ),
            path(
                "radius/group/<uuid:pk>/",
                get_view("radius_group_detail"),
                name="radius_group_detail",
            ),
            path(
                "users/user/<str:user_pk>/radius-group/",
                get_view("radius_user_group_list"),
                name="radius_user_group_list",
            ),
            path(
                "users/user/<str:user_pk>/radius-group/<uuid:pk>/",
                get_view("radius_user_group_detail"),
                name="radius_user_group_detail",
            ),
        ]
    else:
        return []
