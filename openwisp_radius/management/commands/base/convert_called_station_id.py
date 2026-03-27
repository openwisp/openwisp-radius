import logging
import re
from uuid import UUID

import openvpn_status
import swapper
from django.core.management import BaseCommand
from Exscript.protocols import telnetlib
from netaddr import EUI, AddrFormatError, mac_unix

from .... import settings as app_settings
from ....base.models import sanitize_mac_address
from ....utils import load_model

RE_VIRTUAL_ADDR_MAC = re.compile("^{0}:{0}:{0}:{0}:{0}:{0}".format("[a-f0-9]{2}"), re.I)
TELNET_CONNECTION_TIMEOUT = 30  # In seconds

RadiusAccounting = load_model("RadiusAccounting")

logger = logging.getLogger(__name__)


class BaseConvertCalledStationIdCommand(BaseCommand):
    logger = logger

    def _search_mac_address(self, common_name):
        match = RE_VIRTUAL_ADDR_MAC.search(common_name)
        if not match:
            raise IndexError(f"No MAC address found in '{common_name}'")
        return match[0]

    help = "Correct Called Station IDs of Radius Sessions"

    def _get_raw_management_info(self, host, port, password):
        with telnetlib.Telnet(host, port, timeout=TELNET_CONNECTION_TIMEOUT) as tn:
            if password:
                tn.read_until(b"ENTER PASSWORD:", timeout=TELNET_CONNECTION_TIMEOUT)
                tn.write(password.encode("ascii") + b"\n")
            tn.read_until(
                b">INFO:OpenVPN Management Interface Version 3 -- type "
                b"'help' for more info",
                timeout=TELNET_CONNECTION_TIMEOUT,
            )
            tn.write("status".encode("ascii") + b"\n")
            raw_management_info = tn.read_until(
                b"END", timeout=TELNET_CONNECTION_TIMEOUT
            )
        return raw_management_info

    def _get_openvpn_routing_info(self, host, port=7505, password=None):
        try:
            raw_info = self._get_raw_management_info(host, port, password)
        except ConnectionRefusedError:
            BaseConvertCalledStationIdCommand.logger.warning(
                "Unable to establish telnet connection to "
                f"{host} on {port}. Skipping!"
            )
            return {}
        except (OSError, TimeoutError, EOFError) as error:
            BaseConvertCalledStationIdCommand.logger.warning(
                f"Error encountered while connecting to {host}:{port}: {error}. "
                "Skipping!"
            )
            return {}
        except Exception:
            BaseConvertCalledStationIdCommand.logger.warning(
                f"Error encountered while connecting to {host}:{port}. Skipping!"
            )
            return {}
        try:
            parsed_info = openvpn_status.parse_status(raw_info)
            return parsed_info.routing_table
        except openvpn_status.ParsingError as error:
            BaseConvertCalledStationIdCommand.logger.warning(
                "Unable to parse information received from "
                f"{host}:{port}. ParsingError: {error}. Skipping!"
            )
            return {}

    def _get_radius_session(self, unique_id):
        try:
            return RadiusAccounting.objects.select_related("organization").get(
                unique_id=unique_id
            )
        except RadiusAccounting.DoesNotExist:
            BaseConvertCalledStationIdCommand.logger.warning(
                f'RadiusAccount object with unique_id "{unique_id}" does not exist.'
            )

    def _get_called_station_setting(self, radius_session):
        try:
            organization = radius_session.organization
            org_id = str(organization.id)
            if org_id in app_settings.CALLED_STATION_IDS:
                return {org_id: app_settings.CALLED_STATION_IDS[org_id]}
            # organization slug is maintained for backward compatibility
            # but will removed in future versions
            return {org_id: app_settings.CALLED_STATION_IDS[organization.slug]}
        except KeyError:
            BaseConvertCalledStationIdCommand.logger.error(
                "OPENWISP_RADIUS_CALLED_STATION_IDS does not contain setting "
                f'for "{radius_session.organization.name}" organization'
            )

    def add_arguments(self, parser):
        parser.add_argument("--unique_id", action="store", type=str, default="")

    def handle(self, *args, **options):
        unique_id = options.get("unique_id")
        # command run for all sessions
        if not unique_id:
            called_station_id_setting = app_settings.CALLED_STATION_IDS
        # command run for specific session
        else:
            input_radius_session = self._get_radius_session(unique_id)
            if not input_radius_session:
                return
            called_station_id_setting = self._get_called_station_setting(
                input_radius_session
            )
            if not called_station_id_setting:
                return

        for org, config in called_station_id_setting.items():
            routing_dict = {}
            for openvpn_config in config["openvpn_config"]:
                raw_routing = self.__class__._get_openvpn_routing_info(
                    self,
                    openvpn_config["host"],
                    openvpn_config.get("port", 7505),
                    openvpn_config.get("password", None),
                )
                normalized_routing = {}
                for k, v in raw_routing.items():
                    try:
                        norm_key = str(EUI(k, dialect=mac_unix)).lower()
                    except Exception:
                        norm_key = k.lower()
                    normalized_routing[norm_key] = v
                routing_dict.update(normalized_routing)
            if not routing_dict:
                BaseConvertCalledStationIdCommand.logger.info(
                    f'No routing information found for "{org}" organization'
                )
                continue

            if unique_id:
                qs = [input_radius_session]
            else:
                qs = self._get_unconverted_sessions(org, config["unconverted_ids"])
            for radius_session in qs:
                try:
                    lookup_key = str(
                        EUI(radius_session.calling_station_id, dialect=mac_unix)
                    ).lower()
                except (AddrFormatError, ValueError, TypeError):
                    BaseConvertCalledStationIdCommand.logger.warning(
                        f"Invalid calling_station_id for session "
                        f"{radius_session.session_id}. Skipping!"
                    )
                    continue
                if lookup_key not in routing_dict:

                    def _strip_leading_zeros(k):
                        parts = k.split(":")
                        return ":".join([p.lstrip("0") or "0" for p in parts])

                    alt_key = _strip_leading_zeros(lookup_key)
                    if alt_key in routing_dict:
                        routing_dict[lookup_key] = routing_dict[alt_key]
                    else:
                        BaseConvertCalledStationIdCommand.logger.warning(
                            "Failed to find routing information for "
                            f"{radius_session.session_id}. Skipping!"
                        )
                        continue

                common_name = routing_dict[lookup_key].common_name

                try:
                    mac_address = self._search_mac_address(common_name)
                except (TypeError, IndexError):
                    BaseConvertCalledStationIdCommand.logger.warning(
                        f'Failed to find a MAC address in "{common_name}". '
                        f"Skipping {radius_session.session_id}!"
                    )
                    continue
                radius_session.called_station_id = sanitize_mac_address(mac_address)
                radius_session.save()

    def _get_unconverted_sessions(self, org, unconverted_ids):
        """
        Get unconverted sessions for the given organization and unconverted IDs.
        """

        if isinstance(org, str):
            try:
                org_uuid = UUID(org)
            except ValueError:
                Organization = swapper.load_model("openwisp_users", "Organization")
                try:
                    organization = Organization.objects.get(slug=org)
                    org_uuid = organization.id
                except Organization.DoesNotExist:
                    self.logger.warning(f"Organization '{org}' not found")
                    return RadiusAccounting.objects.none()
        else:
            org_uuid = org.id

        return RadiusAccounting.objects.filter(
            organization_id=org_uuid,
            called_station_id__in=unconverted_ids,
            stop_time__isnull=True,
        )


# monkey patching for openvpn_status begins
def parse_virtual_address(virtual_address):
    return openvpn_status.utils.parse_vaddr(virtual_address.split("@")[0])


openvpn_status.utils.DATETIME_FORMAT_OPENVPN = app_settings.OPENVPN_DATETIME_FORMAT
openvpn_status.models.Routing.virtual_address = (
    openvpn_status.descriptors.LabelProperty(
        "Virtual Address", input_type=parse_virtual_address
    ),
)[0]
# monkey patching for openvpn_status ends
