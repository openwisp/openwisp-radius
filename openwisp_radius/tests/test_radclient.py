from unittest.mock import Mock, patch

from django.test import TestCase
from pyrad.client import Client, Timeout
from pyrad.packet import CoAACK, CoANAK

from .. import settings as app_settings
from ..radclient.client import CoaPacket, RadClient


class TestRadClient(TestCase):
    def _get_client(self):
        return RadClient(
            host='127.0.0.1',
            radsecret='testing',
        )

    def test_clean_attributes(self):
        client = self._get_client()
        attrs = {
            'Max-Daily-Session-Traffic': '3000000',
            'Max-Daily-Session': '10800',
            'WISPr-Bandwidth-Max-Down': '30000',
        }
        cleaned_attrs = client.clean_attributes(attrs)
        self.assertEqual(
            cleaned_attrs,
            {
                'Session-Timeout': '10800',
                app_settings.TRAFFIC_COUNTER_REPLY_NAME: '3000000',
                'WISPr-Bandwidth-Max-Down': '30000',
            },
        )

    @patch('logging.Logger.info')
    def test_perform_change_of_authorization(self, mocked_logger):
        client = self._get_client()
        attrs = {
            'Session-Timeout': '10800',
        }
        mocked_coaack = Mock()
        mocked_coaack.code = CoAACK
        mocked_coanak = Mock()
        mocked_coanak.code = CoANAK

        with self.subTest('Test request timed out'):
            with patch.object(Client, '_SendPacket', side_effect=Timeout):
                result = client.perform_change_of_authorization(attrs)
                self.assertEqual(result, False)
            mocked_logger.assert_called_with(
                f'Failed to perform CoA with {client.client.server}'
                f' with payload {attrs}. Error: CoA request timed out.'
            )

        mocked_logger.reset_mock()
        with self.subTest('Test CoAACK'):
            with patch.object(Client, '_SendPacket', return_value=mocked_coaack):
                result = client.perform_change_of_authorization(attrs)
                self.assertEqual(result, True)
            mocked_logger.assert_called_with(
                f'CoAACK received from {client.client.server} for payload: {attrs}'
            )

        with self.subTest('Test CoANAK'):
            with patch.object(Client, '_SendPacket', return_value=mocked_coanak):
                result = client.perform_change_of_authorization(attrs)
                self.assertEqual(result, False)
            mocked_logger.assert_called_with(
                f'CoANAK received from {client.client.server} for payload: {attrs}'
            )

    def test_coa_packet(self):
        client = self._get_client()
        packet = CoaPacket(dict=client.client.dict)
        encoded_values = packet._EncodeKeyValues(*('Session-Timeout', ''))
        self.assertEqual(encoded_values, ('Session-Timeout', ''))
        encoded_values = packet._EncodeKeyValues(*('Session-Timeout', '10'))
        self.assertEqual(encoded_values, (27, [b'\x00\x00\x00\n']))
