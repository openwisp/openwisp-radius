from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^authorize/$', views.authorize, name='authorize'),
    url(r'^postauth/$', views.postauth, name='postauth'),
    url(r'^accounting/$', views.accounting, name='accounting'),
    url(r'^batch/$', views.batch, name='batch'),
    # registration differentiated by organization
    url(r'^registration/(?P<slug>[\w-]+)/$', views.register, name='rest_register'),
]
