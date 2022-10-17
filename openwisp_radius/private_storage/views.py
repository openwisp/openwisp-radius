from private_storage.views import PrivateStorageDetailView

from ..settings import PRIVATE_STORAGE_INSTANCE
from ..utils import load_model


class RadiusBatchCsvDownloadView(PrivateStorageDetailView):
    storage = PRIVATE_STORAGE_INSTANCE
    model = load_model('RadiusBatch')
    model_file_field = 'csvfile'
    slug_field = 'csvfile'
    slug_url_kwarg = 'path'

    def can_access_file(self, private_file):
        user = private_file.request.user
        return user.is_superuser or (
            user.is_staff and user.is_manager(self.object.organization)
        )


rad_batch_csv_download_view = RadiusBatchCsvDownloadView.as_view()
