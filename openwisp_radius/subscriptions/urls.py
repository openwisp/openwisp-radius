from django.conf.urls import url

from . import views

app_name = 'subscriptions'

urlpatterns = [
    url(r'^payment/(?P<pk>[^/]+)/$',
        views.payment_details,
        name='process_payment'),
    url(r'^invoice/(?P<pk>\d+)/download/$',
        views.download_invoice,
        name='download_invoice'),
    url(r'^api/v1/plans/$',
        views.plan_pricing,
        name='api_plan_pricing'),
]
