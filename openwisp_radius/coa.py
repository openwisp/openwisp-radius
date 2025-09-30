import ipaddress
import logging

from django.contrib.auth import get_user_model

from .counters.exceptions import MaxQuotaReached
from .radclient.client import RadClient
from .utils import (
    execute_counter_checks,
    get_group_checks,
    get_group_replies,
    load_model,
)

logger = logging.getLogger(__name__)

RadiusAccounting = load_model("RadiusAccounting")
RadiusGroupCheck = load_model("RadiusGroupCheck")
RadiusGroupReply = load_model("RadiusGroupReply")
RadiusGroup = load_model("RadiusGroup")
Nas = load_model("Nas")
User = get_user_model()


class ChangeOfAuthorizationManager:
    """
    Manages Change of Authorization (CoA) operations for RADIUS users.
    Handles counter checks, attribute retrieval, and communication with NAS.
    """

    def get_radsecret_from_radacct(self, rad_acct):
        """
        Get RADIUS secret for a given RadiusAccounting session.
        """
        qs = Nas.objects.filter(organization_id=rad_acct.organization_id).only(
            "name", "secret"
        )
        nas_ip_address = ipaddress.ip_address(rad_acct.nas_ip_address)
        for nas in qs.iterator():
            try:
                if nas_ip_address in ipaddress.ip_network(nas.name):
                    return nas.secret
            except ValueError:
                logger.warning(
                    f'Failed to parse NAS IP network for "{nas.id}" object. Skipping!'
                )

    def get_radius_attributes(self, user, old_group_id, new_group):
        """
        Get RADIUS attributes for CoA operation including both checks and replies.
        Returns dict of attributes.
        """
        attributes = {}
        old_group = (
            RadiusGroup.objects.prefetch_related(
                "radiusgroupcheck_set", "radiusgroupreply_set"
            )
            .filter(id=old_group_id)
            .first()
        )

        # Include all RadiusGroupReplies for the new group
        group_replies = get_group_replies(new_group)
        if group_replies:
            for key, value in group_replies.items():
                attributes[key] = value["value"]
        elif old_group:
            # We need to unset attributes set by the previous group
            old_group_replies = get_group_replies(old_group)
            for reply in old_group_replies:
                attributes[reply] = ""

        # Include replies from the RadiusGroupChecks for the new group
        group_checks = get_group_checks(new_group)
        if group_checks:
            check_results = execute_counter_checks(user, new_group, group_checks)
            for reply, value in check_results.items():
                attributes[reply] = str(value)
        elif old_group:
            # We need to unset attributes set by the previous group
            old_group_checks = get_group_checks(old_group, counters_only=True)
            check_results = execute_counter_checks(
                user, old_group, old_group_checks, raise_quota_exceeded=False
            )
            for reply_name in check_results.keys():
                attributes[reply_name] = ""

        return attributes

    def perform_change_of_authorization(self, user_id, old_group_id, new_group_id):
        """
        Perform Change of Authorization for a user's group change.
        """
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            logger.warning(
                f'Failed to find user with "{user_id}" ID. Skipping CoA operation.'
            )
            return
        try:
            new_rad_group = (
                RadiusGroup.objects.prefetch_related(
                    "radiusgroupcheck_set", "radiusgroupreply_set"
                )
                .select_related("organization", "organization__radius_settings")
                .get(id=new_group_id)
            )
        except RadiusGroup.DoesNotExist:
            logger.warning(
                f'Failed to find RadiusGroup with "{new_group_id}" ID.'
                " Skipping CoA operation."
            )
            return
        org_radius_settings = new_rad_group.organization.radius_settings
        # The coa_enabled value is provided by a FallbackBooleanChoiceField on the
        # model instance and cannot be reliably evaluated inside queryset filters.
        # Evaluate it here on the resolved model instance instead of trying to
        # filter at the database level.
        if not org_radius_settings.coa_enabled:
            logger.info(
                f'CoA is disabled for "{new_rad_group.organization}" organization.'
                " Skipping CoA operation."
            )
            return
        # Check if user has open RadiusAccounting sessions
        open_sessions = RadiusAccounting.objects.filter(
            username=user.username,
            organization_id=new_rad_group.organization_id,
            stop_time__isnull=True,
        )
        if not open_sessions:
            logger.warning(
                f'The user "{user.username} <{user.email}>" does not have any open'
                " RadiusAccounting sessions. Skipping CoA operation."
            )
            return
        attributes = {}
        func = "perform_change_of_authorization"
        operation = "CoA"
        try:
            new_group_attributes = self.get_radius_attributes(
                user, old_group_id, new_rad_group
            )
            if not new_group_attributes:
                # No attributes to send, skip CoA operation
                logger.warning(
                    f'No RADIUS attributes found for "{new_group_id}" RadiusGroup.'
                    " Skipping CoA operation."
                )
                return
            attributes.update(new_group_attributes)
        except MaxQuotaReached:
            func = "perform_disconnect"
            operation = "Disconnect"
        updated_sessions = []
        for session in open_sessions:
            radsecret = self.get_radsecret_from_radacct(session)
            if not radsecret:
                logger.warning(
                    f'Failed to find RADIUS secret for "{session.unique_id}"'
                    " RadiusAccounting object. Skipping CoA operation"
                    " for this session."
                )
                continue
            attributes["User-Name"] = session.username
            client = RadClient(
                host=session.nas_ip_address,
                radsecret=radsecret,
            )
            result = getattr(client, func)(attributes)
            if result is True:
                session.groupname = new_rad_group.name
                updated_sessions.append(session)
            else:
                logger.warning(
                    f'Failed to perform {operation} for "{session.unique_id}"'
                    f' RadiusAccounting object of "{user}" user'
                )
        RadiusAccounting.objects.bulk_update(updated_sessions, fields=["groupname"])


coa_manager = ChangeOfAuthorizationManager()
