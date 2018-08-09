from django.conf.urls import include, url

from .api import urls as api

app_name = 'freeradius'
urlpatterns = [
    url(r'^accounts/', include('openwisp_users.accounts.urls')),
    url(r'api/v1/', include(api))
]
