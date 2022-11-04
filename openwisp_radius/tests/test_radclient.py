from unittest import TestCase
from unittest.mock import patch

from pyrad.client import Client, Timeout

from .. import settings as app_settings
from ..radclient.client import RadClient


class TestRadClient(TestCase):
    def test_perform_change_of_authorization(self):
        client = RadClient(
            host='127.0.0.1',
            radsecret='testing',
            dicts=app_settings.RADCLIENT_ATTRIBUTE_DICTIONARIES,
        )

        with self.subTest('Test sending CoA packet timed out'):
            with patch.object(Client, 'SendPacket', side_effect=Timeout):
                result = client.perform_change_of_authorization(attributes={})
                self.assertEqual(result, False)

    def test_clean_attributes(self):
        client = RadClient(
            host='127.0.0.1',
            radsecret='testing',
            dicts=app_settings.RADCLIENT_ATTRIBUTE_DICTIONARIES,
        )
        attrs = {
            'Max-Daily-Session-Traffic': ':=3000000',
            'Max-Daily-Session': ':=10800',
            'WISPr-Bandwidth-Max-Down': ':=30000',
        }
        cleaned_attrs = client.clean_attributes(attrs)
        self.assertEqual(
            cleaned_attrs,
            {
                'Max-Daily-Session': ':=10800',
                'Max-Daily-Session-Traffic': ':=3000000',
                'WISPr-Bandwidth-Max-Down': ':=30000',
            },
        )
