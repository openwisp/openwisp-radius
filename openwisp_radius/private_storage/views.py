from django.utils.translation import gettext_lazy as _
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from private_storage.views import PrivateStorageDetailView
from rest_framework.views import APIView

from ..settings import PRIVATE_STORAGE_INSTANCE
from ..utils import load_model


class RadiusBatchCsvDownloadView(PrivateStorageDetailView):
    storage = PRIVATE_STORAGE_INSTANCE
    model = load_model("RadiusBatch")
    model_file_field = "csvfile"
    slug_field = "csvfile"
    slug_url_kwarg = "path"

    def can_access_file(self, private_file):
        user = private_file.request.user
        return user.is_superuser or (
            user.is_staff and user.is_manager(self.object.organization)
        )


rad_batch_csv_download_view = RadiusBatchCsvDownloadView.as_view()


class RadiusBatchCsvDownloadAPIView(APIView):
    @swagger_auto_schema(
        operation_id="radius_organization_batch_csv_read",
        operation_description=_(
            "Download the CSV export file for a specific RADIUS batch."
        ),
        manual_parameters=[
            openapi.Parameter(
                "slug",
                openapi.IN_PATH,
                description=_("Organization slug"),
                type=openapi.TYPE_STRING,
            ),
        ],
        responses={
            200: openapi.Response(
                description=_("CSV file"), schema=openapi.Schema(type=openapi.TYPE_FILE)
            ),
        },
        tags=["radius"],
    )
    def get(self, request, slug, pk, filename, *args, **kwargs):
        return rad_batch_csv_download_view(request, pk=pk, filename=filename, **kwargs)
