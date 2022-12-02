import logging
import os

from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad.packet import CoAACK, CoANAK
from pyrad.packet import CoAPacket as BaseCoAPacket

from .. import settings as app_settings

logger = logging.getLogger(__name__)

ATTRIBUTE_MAP = {
    # OpenWISP Check Attribute: Coova-Chilli Attribute
    'Max-Daily-Session-Traffic': app_settings.TRAFFIC_COUNTER_REPLY_NAME,
    'Max-Daily-Session': 'Session-Timeout',
}
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DICTIONARY = os.path.join(MODULE_DIR, 'dictionary')


class CoaPacket(BaseCoAPacket):
    def _EncodeKeyValues(self, key, values):
        if values == '':
            return (key, values)
        return super()._EncodeKeyValues(key, values)


class RadClient(object):
    def __init__(self, host, radsecret):
        self.client = Client(
            server=host,
            secret=radsecret.encode(),
            dict=Dictionary(*self.get_dictionaries()),
        )

    def get_dictionaries(self):
        return [DEFAULT_DICTIONARY] + app_settings.RADCLIENT_ATTRIBUTE_DICTIONARIES

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
        request = CoaPacket(secret=self.client.secret, dict=self.client.dict, **attrs)
        try:
            response = self.client._SendPacket(request, port=self.client.coaport)
        except Timeout:
            logger.info(
                f'Failed to perform CoA with {self.client.server}'
                f' with payload {attrs}. Error: CoA request timed out.'
            )
            return False
        if response.code == CoAACK:
            logger.info(
                f'CoAACK received from {self.client.server} for payload: {attrs}'
            )
            return True
        if response.code == CoANAK:
            logger.info(
                f'CoANAK received from {self.client.server} for payload: {attrs}'
            )
        return False
