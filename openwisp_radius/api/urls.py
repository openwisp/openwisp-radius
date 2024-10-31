from django.urls import path

from .. import settings as app_settings
from . import views


def get_api_urls(api_views=None):
    if not api_views:
        api_views = views
    if app_settings.RADIUS_API:
        return [
            path('freeradius/authorize/', api_views.authorize, name='authorize'),
            path('freeradius/postauth/', api_views.postauth, name='postauth'),
            path('freeradius/accounting/', api_views.accounting, name='accounting'),
            # registration differentiated by organization
            path(
                'radius/organization/<slug:slug>/account/',
                api_views.register,
                name='rest_register',
            ),
            # password reset
            path(
                'radius/organization/<slug:slug>/account/password/reset/confirm/',
                api_views.password_reset_confirm,
                name='rest_password_reset_confirm',
            ),
            path(
                'radius/organization/<slug:slug>/account/password/reset/',
                api_views.password_reset,
                name='rest_password_reset',
            ),
            path(
                'radius/organization/<slug:slug>/account/password/change/',
                api_views.password_change,
                name='rest_password_change',
            ),
            # obtaining the user token is also different for every org
            path(
                'radius/organization/<slug:slug>/account/token/',
                api_views.obtain_auth_token,
                name='user_auth_token',
            ),
            path(
                'radius/organization/<slug:slug>/account/token/validate/',
                api_views.validate_auth_token,
                name='validate_auth_token',
            ),
            path(
                'radius/organization/<slug:slug>/account/session/',
                api_views.user_accounting,
                name='user_accounting',
            ),
            path(
                'radius/organization/<slug:slug>/account/usage/',
                api_views.user_radius_usage,
                name='user_radius_usage',
            ),
            # generate new sms phone token
            path(
                'radius/organization/<slug:slug>/account/phone/token/',
                api_views.create_phone_token,
                name='phone_token_create',
            ),
            path(
                'radius/organization/<slug:slug>/account/phone/token/active/',
                api_views.get_phone_token_status,
                name='phone_token_status',
            ),
            path(
                'radius/organization/<slug:slug>/account/phone/verify/',
                api_views.validate_phone_token,
                name='phone_token_validate',
            ),

            path(
                'radius/organization/<slug:slug>/groups/',
                views.radius_group_list, 
                name='radius_group_list'), # Radius Groups
            
            path(
                'radius/organization/<slug:slug>/groups/<uuid:user>/',
                api_views.radius_user_group_list, 
                name='radius_user_group_list')
            
            # allow changing phone number
            path(
                'radius/organization/<slug:slug>/account/phone/change/',
                api_views.change_phone_number,
                name='phone_number_change',
            ),
            
            path(
                'radius/organization/<slug:slug>/batch/<uuid:pk>/pdf/',
                api_views.download_rad_batch_pdf,
                name='download_rad_batch_pdf',
            ),
            # list radius groups
            path(
                'radius/product/plans/',
                api_views.radius_product_plans,
                name='radius_product_plans',
            ),
            # update user plan
            path(
                'radius/user/<uuid:user>/plan/',
                api_views.radius_user_plan_update,
                name='radius_user_plan_update',
            ),
            # list user plans
            path(
                'radius/product/plans/<uuid:user>/',
                api_views.radius_user_plan_list,
                name='radius_user_plan_list',
            ),

            path(
                'radius/groups/',
                api_views.radius_group_list_all, 
                name='radius_group_list_all'),  # Renamed for clarity
            path(
                'radius/user/<uuid:user>/group/', 
                api_views.radius_user_group_update, name='radius_user_group_update'),  # Renamed for clarity
                path('radius/batch/', api_views.batch, 
                name='batch'),
        ]
    else:
        return []
