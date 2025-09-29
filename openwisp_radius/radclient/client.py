import logging
import os

from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad.packet import CoAACK, CoANAK
from pyrad.packet import CoAPacket as BaseCoAPacket
from pyrad.packet import DisconnectACK, DisconnectNAK, DisconnectRequest

from .. import settings as app_settings

logger = logging.getLogger(__name__)

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DICTIONARY = os.path.join(MODULE_DIR, "dictionary")


class CoaPacket(BaseCoAPacket):
    def _EncodeKeyValues(self, key, values):
        if values == "":
            return (key, values)
        return super()._EncodeKeyValues(key, values)

    def AddAttribute(self, key, value):
        try:
            return super().AddAttribute(key, value)
        except KeyError:
            # Skip attributes not found in the dictionary
            logger.warning(f"RADIUS attribute '{key}' not found in dictionary")


class DisconnectPacket(BaseCoAPacket):
    def __init__(self, code=DisconnectRequest, *args, **kwargs):
        super().__init__(code=code, *args, **kwargs)


class RadClient(object):
    def __init__(self, host, radsecret):
        self.client = Client(
            server=host,
            secret=radsecret.encode(),
            dict=Dictionary(*self.get_dictionaries()),
        )

    def get_dictionaries(self):
        return [DEFAULT_DICTIONARY] + app_settings.RADCLIENT_ATTRIBUTE_DICTIONARIES

    def _send_radius_request(
        self, packet_class, attributes, operation_name, success_code, nak_code
    ):
        """
        Helper method to send RADIUS requests and handle responses.

        Args:
            packet_class: The packet class to use (CoaPacket or DisconnectPacket)
            attributes: Dictionary of attributes to send
            operation_name: Name of the operation for logging (e.g., "CoA")
            success_code: Expected success response code
            nak_code: Expected NAK response code

        Returns:
            bool: True if request was accepted by NAS, False otherwise
        """
        request = packet_class(
            secret=self.client.secret, dict=self.client.dict, **attributes
        )
        try:
            response = self.client._SendPacket(request, port=self.client.coaport)
        except Timeout:
            logger.info(
                f"Failed to perform {operation_name} with {self.client.server}"
                f" with payload {attributes}. Error: {operation_name} request"
                " timed out."
            )
            return False
        if response.code == success_code:
            logger.info(
                f"{operation_name}ACK received from {self.client.server} "
                f"for payload: {attributes}"
            )
            return True
        if response.code == nak_code:
            logger.info(
                f"{operation_name}NAK received from {self.client.server} "
                f"for payload: {attributes}"
            )
        return False

    def perform_change_of_authorization(self, attributes):
        """
        Returns True if CoA request was accepted by NAS.
        Otherwise, returns False.
        """
        return self._send_radius_request(CoaPacket, attributes, "CoA", CoAACK, CoANAK)

    def perform_disconnect(self, attributes):
        """
        Sends a Disconnect Message to NAS.
        Returns True if Disconnect request was accepted by NAS.
        Otherwise, returns False.
        """
        return self._send_radius_request(
            DisconnectPacket, attributes, "Disconnect", DisconnectACK, DisconnectNAK
        )
