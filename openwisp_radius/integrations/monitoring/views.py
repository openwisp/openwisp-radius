from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.generics import ListAPIView
from swapper import load_model

from openwisp_radius.api.freeradius_views import (
    AccountingFilter,
    AccountingViewPagination,
)
from openwisp_users.api.mixins import FilterByOrganizationManaged, ProtectedAPIMixin

from .serializers import MonitoringRadiusAccountingSerializer

RadiusAccounting = load_model("openwisp_radius", "RadiusAccounting")


class MonitoringAccountingView(
    ProtectedAPIMixin, FilterByOrganizationManaged, ListAPIView
):
    """
    API view for RADIUS accounting in monitoring integration.
    Uses server-side datetime formatting for consistency with Django admin.
    """

    throttle_scope = "radius_accounting_list"
    serializer_class = MonitoringRadiusAccountingSerializer
    pagination_class = AccountingViewPagination
    filter_backends = (DjangoFilterBackend,)
    filterset_class = AccountingFilter
    queryset = RadiusAccounting.objects.all().order_by("-start_time")
