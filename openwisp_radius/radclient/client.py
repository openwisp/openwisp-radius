from pyrad.client import Client, Timeout
from pyrad.dictionary import Dictionary
from pyrad.packet import CoAACK

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
                attr[ATTRIBUTE_MAP[key]] = attributes[value]
            except KeyError:
                attr[key] = value
        return attr

    def perform_change_of_authorization(self, attributes):
        """
        Returns True if CoA request was accepted by NAS.
        Otherwise, returns False.
        """
        attr = self.clean_attributes(attributes)
        request = self.client.CreateCoAPacket(**attr)
        try:
            response = self.client.SendPacket(request)
        except Timeout:
            return False
        return response.status_code == CoAACK
