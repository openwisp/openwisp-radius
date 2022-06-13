from urllib.parse import urljoin

from django.conf import settings
from private_storage.storage.files import PrivateFileSystemStorage

from ..settings import CSV_URL_PATH, RADIUS_API_BASEURL

private_file_system_storage = PrivateFileSystemStorage(
    location=settings.PRIVATE_STORAGE_ROOT,
    base_url=urljoin(RADIUS_API_BASEURL, CSV_URL_PATH),
)
