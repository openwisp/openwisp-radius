from django.conf.urls import url

from . import views


urlpatterns = [
    url(r'^payment/(?P<pk>[^/]+)/$',
        views.payment_details,
        name='process_payment'),
    url(r'^api/v1/plans/$',
        views.plan_pricing,
        name='api_plan_pricing'),
]
