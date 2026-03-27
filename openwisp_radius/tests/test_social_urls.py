from unittest.mock import patch

from django.test import TestCase, override_settings
from django.urls import resolve

from openwisp_radius.social.urls import get_social_urls
from openwisp_radius.tests.test_social import TestSocial


class TestSocialUrls(TestSocial, TestCase):
    def test_get_social_urls_not_configured(self):
        with patch("openwisp_radius.settings.SOCIAL_REGISTRATION_CONFIGURED", False):
            urls = get_social_urls()
            self.assertEqual(urls, [])

    @override_settings(ROOT_URLCONF=__name__)
    def test_get_social_urls_configured(self):
        with patch("openwisp_radius.settings.SOCIAL_REGISTRATION_CONFIGURED", True):
            urls = get_social_urls()
            self.assertTrue(len(urls) > 0)
            redirect_url_found = any(p.name == "redirect_cp" for p in urls)
            self.assertTrue(redirect_url_found)

    def test_get_social_urls_defaults(self):
        with patch("openwisp_radius.settings.SOCIAL_REGISTRATION_CONFIGURED", True):
            urls = get_social_urls(social_views=None)
            self.assertTrue(len(urls) > 0)
