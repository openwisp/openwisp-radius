from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^authorize/$', views.authorize, name='authorize'),
    url(r'^postauth/$', views.postauth, name='postauth'),
    url(r'^accounting/$', views.accounting, name='accounting'),
    url(r'^batch/$', views.batch, name='batch'),
    # registration differentiated by organization
    url(r'^(?P<slug>[\w-]+)/account/$',
        views.register,
        name='rest_register'),
    # password reset
    url(r'^(?P<slug>[\w-]+)/account/password/reset/confirm/$',
        views.password_reset_confirm,
        name='rest_password_reset_confirm'),
    url(r'^(?P<slug>[\w-]+)/account/password/reset/$',
        views.password_reset,
        name='rest_password_reset'),
    url(r'^(?P<slug>[\w-]+)/account/password/change/$',
        views.password_change,
        name='rest_password_change'),
    # obtaining the user token is also different for every org
    url(r'^(?P<slug>[\w-]+)/account/token/$',
        views.obtain_auth_token,
        name='user_auth_token'),
    url(r'^(?P<slug>[\w-]+)/account/token/validate/$',
        views.validate_auth_token,
        name='validate_auth_token'),
    # generate new sms phone token
    url(r'^create-phone-token/(?P<slug>[\w-]+)/$',
        views.create_phone_token,
        name='phone_token_create'),
    url(r'^validate-phone-token/(?P<slug>[\w-]+)/$',
        views.validate_phone_token,
        name='phone_token_validate'),
]
