from django.conf.urls import url

from . import views


def get_api_urls(api_views=None):
    if not api_views:
        api_views = views
    return [
        url(r'^authorize/$', api_views.authorize, name='authorize'),
        url(r'^postauth/$', api_views.postauth, name='postauth'),
        url(r'^accounting/$', api_views.accounting, name='accounting'),
        url(r'^batch/$', api_views.batch, name='batch'),
        # registration differentiated by organization
        url(r'^(?P<slug>[\w-]+)/account/$', api_views.register, name='rest_register'),
        # password reset
        url(
            r'^(?P<slug>[\w-]+)/account/password/reset/confirm/$',
            api_views.password_reset_confirm,
            name='rest_password_reset_confirm',
        ),
        url(
            r'^(?P<slug>[\w-]+)/account/password/reset/$',
            api_views.password_reset,
            name='rest_password_reset',
        ),
        url(
            r'^(?P<slug>[\w-]+)/account/password/change/$',
            api_views.password_change,
            name='rest_password_change',
        ),
        # obtaining the user token is also different for every org
        url(
            r'^(?P<slug>[\w-]+)/account/token/$',
            api_views.obtain_auth_token,
            name='user_auth_token',
        ),
        url(
            r'^(?P<slug>[\w-]+)/account/token/validate/$',
            api_views.validate_auth_token,
            name='validate_auth_token',
        ),
        url(
            r'^(?P<slug>[\w-]+)/account/session/$',
            api_views.user_accounting,
            name='user_accounting',
        ),
        # generate new sms phone token
        url(
            r'^(?P<slug>[\w-]+)/account/phone/token/$',
            api_views.create_phone_token,
            name='phone_token_create',
        ),
        url(
            r'^(?P<slug>[\w-]+)/account/phone/verify/$',
            api_views.validate_phone_token,
            name='phone_token_validate',
        ),
        # allow changing phone number
        url(
            r'^(?P<slug>[\w-]+)/account/phone/change/$',
            api_views.change_phone_number,
            name='phone_number_change',
        ),
    ]
