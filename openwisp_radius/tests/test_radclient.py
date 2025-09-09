from unittest.mock import Mock, patch

from django.test import TestCase
from pyrad.client import Client, Timeout
from pyrad.packet import CoAACK, CoANAK, DisconnectACK, DisconnectNAK, DisconnectRequest

from ..radclient.client import CoaPacket, DisconnectPacket, RadClient


class TestRadClient(TestCase):
    def _get_client(self):
        return RadClient(
            host="127.0.0.1",
            radsecret="testing",
        )

    @patch("logging.Logger.info")
    def test_perform_change_of_authorization(self, mocked_logger):
        client = self._get_client()
        attrs = {
            "Session-Timeout": "10800",
        }
        mocked_coaack = Mock()
        mocked_coaack.code = CoAACK
        mocked_coanak = Mock()
        mocked_coanak.code = CoANAK

        with self.subTest("Test request timed out"):
            with patch.object(Client, "_SendPacket", side_effect=Timeout):
                result = client.perform_change_of_authorization(attrs)
                self.assertEqual(result, False)
            mocked_logger.assert_called_with(
                f"Failed to perform CoA with {client.client.server}"
                f" with payload {attrs}. Error: CoA request timed out."
            )

        mocked_logger.reset_mock()
        with self.subTest("Test CoAACK"):
            with patch.object(Client, "_SendPacket", return_value=mocked_coaack):
                result = client.perform_change_of_authorization(attrs)
                self.assertEqual(result, True)
            mocked_logger.assert_called_with(
                f"CoAACK received from {client.client.server} for payload: {attrs}"
            )

        with self.subTest("Test CoANAK"):
            with patch.object(Client, "_SendPacket", return_value=mocked_coanak):
                result = client.perform_change_of_authorization(attrs)
                self.assertEqual(result, False)
            mocked_logger.assert_called_with(
                f"CoANAK received from {client.client.server} for payload: {attrs}"
            )

    def test_coa_packet(self):
        client = self._get_client()
        packet = CoaPacket(dict=client.client.dict)
        encoded_values = packet._EncodeKeyValues(*("Session-Timeout", ""))
        self.assertEqual(encoded_values, ("Session-Timeout", ""))
        encoded_values = packet._EncodeKeyValues(*("Session-Timeout", "10"))
        self.assertEqual(encoded_values, (27, [b"\x00\x00\x00\n"]))

    def test_disconnect_packet(self):
        client = self._get_client()
        packet = DisconnectPacket(dict=client.client.dict)

        self.assertEqual(packet.code, DisconnectRequest)
        encoded_values = packet._EncodeKeyValues(*("User-Name", ""))
        self.assertEqual(encoded_values, (1, [b""]))
        encoded_values = packet._EncodeKeyValues(*("User-Name", "testuser"))
        self.assertEqual(encoded_values, (1, [b"testuser"]))

    @patch("logging.Logger.warning")
    def test_coa_packet_add_attribute_error_handling(self, mocked_logger):
        client = self._get_client()
        packet = CoaPacket(dict=client.client.dict)
        packet.AddAttribute("User-Name", "testuser")
        packet.AddAttribute("Unknown-Attribute", "test-value")
        mocked_logger.assert_called_with(
            "RADIUS attribute 'Unknown-Attribute' not found in dictionary"
        )
        self.assertEqual(len(packet), 1)

    @patch("logging.Logger.info")
    def test_perform_disconnect(self, mocked_logger):
        client = self._get_client()
        attrs = {
            "User-Name": "testuser",
        }
        mocked_disconnect_ack = Mock()
        mocked_disconnect_ack.code = DisconnectACK
        mocked_disconnect_nak = Mock()
        mocked_disconnect_nak.code = DisconnectNAK

        with self.subTest("Test request timed out"):
            with patch.object(Client, "_SendPacket", side_effect=Timeout):
                result = client.perform_disconnect(attrs)
                self.assertEqual(result, False)
            mocked_logger.assert_called_with(
                f"Failed to perform Disconnect with {client.client.server}"
                f" with payload {attrs}. Error: Disconnect request timed out."
            )

        mocked_logger.reset_mock()
        with self.subTest("Test DisconnectACK"):
            with patch.object(
                Client, "_SendPacket", return_value=mocked_disconnect_ack
            ):
                result = client.perform_disconnect(attrs)
                self.assertEqual(result, True)
            mocked_logger.assert_called_with(
                f"DisconnectACK received from {client.client.server} "
                f"for payload: {attrs}"
            )

        mocked_logger.reset_mock()
        with self.subTest("Test DisconnectNAK"):
            with patch.object(
                Client, "_SendPacket", return_value=mocked_disconnect_nak
            ):
                result = client.perform_disconnect(attrs)
                self.assertEqual(result, False)
            mocked_logger.assert_called_with(
                f"DisconnectNAK received from {client.client.server} "
                f"for payload: {attrs}"
            )
