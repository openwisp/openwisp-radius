from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from private_storage.views import PrivateStorageDetailView
from rest_framework.views import APIView

from ..settings import PRIVATE_STORAGE_INSTANCE
from ..utils import load_model


class RadiusBatchCsvDownloadView(PrivateStorageDetailView):
    storage = PRIVATE_STORAGE_INSTANCE
    model = load_model("RadiusBatch")
    model_file_field = "csvfile"
    slug_field = "csvfile"
    slug_url_kwarg = "filename"

    def can_access_file(self, private_file):
        user = private_file.request.user
        return user.is_superuser or (
            user.is_staff and user.is_manager(self.object.organization)
        )


rad_batch_csv_download_view = RadiusBatchCsvDownloadView.as_view()


# this is a drf wrapper view
@extend_schema(
    operation_id="radius_organization_batch_csv_read",
    description="Download the CSV export file for a specific RADIUS batch.",
    parameters=[
        OpenApiParameter(
            name="slug",
            type=str,
            location=OpenApiParameter.PATH,
            description="Organization slug",
        ),
        OpenApiParameter(
            name="pk",
            type=str,
            location=OpenApiParameter.PATH,
            description="Batch UUID",
        ),
        OpenApiParameter(
            name="filename",
            type=str,
            location=OpenApiParameter.PATH,
            description="CSV filename",
        ),
    ],
    responses={
        200: OpenApiResponse(description="CSV file", response=OpenApiTypes.BINARY)
    },
    tags=["radius"],
)
class RadiusBatchCsvDownloadAPIView(APIView):
    def get(self, request, pk, filename):
        view = RadiusBatchCsvDownloadView.as_view()
        return view(request, pk=pk, filename=filename)
