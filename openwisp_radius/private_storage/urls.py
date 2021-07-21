from urllib.parse import urljoin

from django.urls import path

from .. import settings as app_settings
from . import views

app_name = 'radius_privstore'

urlpatterns = [
    path(
        urljoin(app_settings.CSV_URL_PATH, '<path:csvfile>'),
        views.rad_batch_csv_download_view,
        name='serve_private_file',
    ),
]
