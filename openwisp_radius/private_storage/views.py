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
    pk_url_kwarg = "pk"

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
            "Allows downloading the CSV file used to import users for a "
            "specific batch user creation operation."
        ),
        responses={
            200: openapi.Response(
                description=_("CSV file"), schema=openapi.Schema(type=openapi.TYPE_FILE)
            ),
        },
        tags=["radius"],
    )
    def get(self, request, _slug, pk, *args, **kwargs):
        return rad_batch_csv_download_view(request, pk=pk, **kwargs)


rad_batch_csv_download_api_view = RadiusBatchCsvDownloadAPIView.as_view()
