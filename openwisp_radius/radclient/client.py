import logging

from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad.packet import CoAACK, CoANAK

logger = logging.getLogger(__name__)

ATTRIBUTE_MAP = {
    # OpenWISP Check Attribute: Coova-Chilli Attribute
    'Max-Daily-Session-Traffic': 'ChilliSpot-Max-Input-Octets',
    'Max-Daily-Session': 'Session-Timeout',
}


class RadClient(object):
    def __init__(self, host, radsecret, dicts):
        self.client = Client(
            server=host, secret=radsecret.encode(), dict=Dictionary(*dicts)
        )

    def clean_attributes(self, attributes):
        attr = {}
        for key, value in attributes.items():
            try:
                attr[ATTRIBUTE_MAP[key]] = value
            except KeyError:
                attr[key] = value
        return attr

    def perform_change_of_authorization(self, attributes):
        """
        Returns True if CoA request was accepted by NAS.
        Otherwise, returns False.
        """
        attrs = self.clean_attributes(attributes)
        request = self.client.CreateCoAPacket(**attrs)
        try:
            response = self.client.SendPacket(request)
        except Timeout as error:
            logger.info(
                f'Failed to perform CoA with {self.client.server}'
                f' with payload {attrs}. Error: {error}'
            )
            return False
        if response.code == CoAACK:
            logger.info(
                f'CoAACK received from {self.client.server}' f' for payload: {attrs}'
            )
            return True
        if response.code == CoANAK:
            logger.info(
                f'CoANAK received from {self.client.server}' f' for payload: {attrs}'
            )
        return False
