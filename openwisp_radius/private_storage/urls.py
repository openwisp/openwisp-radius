from urllib.parse import urljoin

from django.urls import path

from .. import settings as app_settings
from . import views


def get_private_store_urls():
    return [
        path(
            urljoin(
                app_settings.CSV_URL_PATH,
                "<slug:slug>/batch/<uuid:pk>/csv/",
            ),
            views.rad_batch_csv_download_api_view,
            name="radius_organization_batch_csv_read",
        ),
        path(
            # Use "path" URL kwarg to make it consistent with
            # django-private-storage. Otherwise, the S3 reverse
            # proxy feature of django-private-storage does
            # not work.
            urljoin(app_settings.CSV_URL_PATH, "<path:path>"),
            views.rad_batch_csv_download_view,
            name="serve_private_file",
        ),
    ]
