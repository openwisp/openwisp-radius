from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^authorize/$', views.authorize, name='authorize'),
    url(r'^postauth/$', views.postauth, name='postauth'),
    url(r'^accounting/$', views.accounting, name='accounting'),
    url(r'^batch/$', views.batch, name='batch'),
    # registration differentiated by organization
    url(r'^registration/(?P<slug>[\w-]+)/$',
        views.register,
        name='rest_register'),
    # password reset
    url(r'^password/reset/confirm/(?P<slug>[\w-]+)/$',
        views.password_reset_confirm,
        name='rest_password_reset_confirm'),
    url(r'^password/reset/(?P<slug>[\w-]+)/$',
        views.password_reset,
        name='rest_password_reset'),
    url(r'^password/change/(?P<slug>[\w-]+)/$',
        views.password_change,
        name='rest_password_change'),
    # obtaining the user token is also different for every org
    url(r'^user-token/(?P<slug>[\w-]+)/$',
        views.obtain_auth_token,
        name='user_token'),
]
