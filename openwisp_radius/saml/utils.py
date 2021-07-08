from urllib.parse import urlparse


def get_url_or_path(url):
    parsed_url = urlparse(url)
    if parsed_url.netloc:
        return f'{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}'
    return parsed_url.path
