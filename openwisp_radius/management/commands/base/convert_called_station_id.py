import logging
import re
import telnetlib

import openvpn_status
from django.core.management import BaseCommand

from ....settings import CALLED_STATION_IDS, OPENVPN_DATETIME_FORMAT
from ....utils import load_model

logger = logging.getLogger(__name__)

RE_VIRTUAL_ADDR_MAC = re.compile(
    u'^{0}:{0}:{0}:{0}:{0}:{0}'.format(u'[a-f0-9]{2}'), re.I
)
TELNET_CONNECTION_TIMEOUT = 10  # In seconds

RadiusAccounting = load_model('RadiusAccounting')


class BaseConvertCalledStationIdCommand(BaseCommand):
    help = 'Correct Called Station IDs of Radius Sessions'

    def _get_raw_management_info(self, host, port, password):
        with telnetlib.Telnet(host, port, timeout=TELNET_CONNECTION_TIMEOUT) as tn:
            if password:
                tn.read_until(b'ENTER PASSWORD:', timeout=TELNET_CONNECTION_TIMEOUT)
                tn.write(password.encode('ascii') + b'\n')
            tn.read_until(
                b'>INFO:OpenVPN Management Interface Version 3 -- type '
                b'\'help\ for more info',
                timeout=TELNET_CONNECTION_TIMEOUT,
            )
            tn.write('status'.encode('ascii') + b'\n')
            raw_management_info = tn.read_until(
                b'END', timeout=TELNET_CONNECTION_TIMEOUT
            )
        return raw_management_info

    def _get_openvpn_routing_info(self, host, port=7505, password=None):
        raw_info = self._get_raw_management_info(host, port, password)
        parsed_info = openvpn_status.parse_status(raw_info)
        return parsed_info.routing_table

    def handle(self, *args, **options):
        for org_slug, config in CALLED_STATION_IDS.items():
            routing_dict = {}
            for openvpn_config in config['openvpn_config']:
                try:
                    routing_dict.update(
                        self._get_openvpn_routing_info(
                            openvpn_config['host'],
                            openvpn_config.get('port', 7505),
                            openvpn_config.get('password', None),
                        )
                    )
                except ConnectionRefusedError:
                    logger.error(
                        'Unable to establish telnet connection to '
                        f'{openvpn_config["host"]} on {openvpn_config["port"]}. '
                        'Skipping!'
                    )
                except openvpn_status.ParsingError as error:
                    logger.error(
                        'Unable to parse information received from '
                        f'{openvpn_config["host"]}. ParsingError: {error}. Skipping!',
                    )
            if not routing_dict:
                logger.info(
                    'No routing information found for '
                    f'organization with "{org_slug}" slug'
                )
                continue

            qs = RadiusAccounting.objects.filter(
                organization__slug=org_slug,
                called_station_id__in=config['unconverted_macs'],
            )
            for radius_session in qs.iterator():
                try:
                    common_name = routing_dict[
                        radius_session.calling_station_id
                    ].common_name
                    mac_address = RE_VIRTUAL_ADDR_MAC.search(common_name)[0]
                    radius_session.called_station_id = mac_address.replace(':', '-')
                except KeyError:
                    logger.warn(
                        'Failed to find routing information for '
                        f'{radius_session.session_id}. Skipping!'
                    )
                except (TypeError, IndexError):
                    logger.warn(
                        f'Failed to find a MAC address in "{common_name}". '
                        f'Skipping {radius_session.session_id}!'
                    )
                else:
                    radius_session.save()


# monkey patching for openvpn_status begins
def parse_virtual_address(virtual_address):
    return openvpn_status.utils.parse_vaddr(virtual_address.split('@')[0])


openvpn_status.utils.DATETIME_FORMAT_OPENVPN = OPENVPN_DATETIME_FORMAT
openvpn_status.models.Routing.virtual_address = (
    openvpn_status.descriptors.LabelProperty(
        u'Virtual Address', input_type=parse_virtual_address
    ),
)[0]
# monkey patching for openvpn_status ends
