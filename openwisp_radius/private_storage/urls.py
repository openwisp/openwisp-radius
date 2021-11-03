from urllib.parse import urljoin

from django.urls import path

from .. import settings as app_settings
from . import views


def get_private_store_urls():
    return [
        path(
            urljoin(app_settings.CSV_URL_PATH, '<path:csvfile>'),
            views.rad_batch_csv_download_view,
            name='serve_private_file',
        )
    ]
