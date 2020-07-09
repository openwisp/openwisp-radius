from private_storage.views import PrivateStorageDetailView

from ..base.models import _get_csv_file_private_storage
from ..utils import load_model


class RadiusBatchCsvDownloadView(PrivateStorageDetailView):
    storage = _get_csv_file_private_storage
    model = load_model('RadiusBatch')
    model_file_field = 'csvfile'
    slug_field = 'csvfile'
    slug_url_kwarg = 'csvfile'

    def can_access_file(self, private_file):
        user = private_file.request.user
        return user.is_superuser or (
            user.is_staff and user.is_manager(self.object.organization)
        )


rad_batch_csv_download_view = RadiusBatchCsvDownloadView.as_view()
