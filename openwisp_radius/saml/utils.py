import logging
from urllib.parse import urlparse

logger = logging.getLogger()


def get_url_or_path(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc:
        return f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}'
    return parsed_url.path


def get_email_from_ava(ava):
    email_keys = (
        'email',
        'mail',
        'uid',
    )
    for key in email_keys:
        email = ava.get(key, None)
        if email is not None:
            return email[0]
    return None
