import ipaddress
import logging
import re

import drf_link_header_pagination
import swapper
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.db import IntegrityError
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from django_filters import rest_framework as filters
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema
from ipware import get_client_ip
from rest_framework import status
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import (
    AuthenticationFailed,
    NotAuthenticated,
    ParseError,
    ValidationError,
)
from rest_framework.generics import CreateAPIView, GenericAPIView, ListCreateAPIView
from rest_framework.response import Response

from openwisp_users.backends import UsersAuthenticationBackend

from .. import registration
from .. import settings as app_settings
from ..counters.base import BaseCounter
from ..counters.exceptions import MaxQuotaReached
from ..signals import radius_accounting_success
from ..utils import (
    execute_counter_checks,
    get_group_checks,
    get_group_replies,
    get_user_group,
    load_model,
)
from .serializers import (
    AuthorizeSerializer,
    RadiusAccountingSerializer,
    RadiusPostAuthSerializer,
)
from .utils import IDVerificationHelper

RE_MAC_ADDR = re.compile(
    "^{0}[:-]{0}[:-]{0}[:-]{0}[:-]{0}[:-]{0}".format("[a-f0-9]{2}"), re.I
)
_TOKEN_AUTH_FAILED = _("Token authentication failed")
# Accounting-Off is not implemented and hence ignored right now
# may be implemented in the future
# Accounting-On is used to close stale sessions
SPECIAL_STATUS_TYPES = ["Accounting-On", "Accounting-Off"]
logger = logging.getLogger(__name__)

RadiusToken = load_model("RadiusToken")
RadiusAccounting = load_model("RadiusAccounting")
OrganizationRadiusSettings = load_model("OrganizationRadiusSettings")
OrganizationUser = swapper.load_model("openwisp_users", "OrganizationUser")
Organization = swapper.load_model("openwisp_users", "Organization")
auth_backend = UsersAuthenticationBackend()


# Radius Accounting
class AccountingFilter(filters.FilterSet):
    start_time = filters.DateTimeFilter(field_name="start_time", lookup_expr="gte")
    stop_time = filters.DateTimeFilter(field_name="stop_time", lookup_expr="lte")
    is_open = filters.BooleanFilter(
        field_name="stop_time", lookup_expr="isnull", label="Is Open"
    )

    class Meta:
        model = RadiusAccounting
        fields = (
            "username",
            "called_station_id",
            "calling_station_id",
            "start_time",
            "stop_time",
            "is_open",
        )


class FreeradiusApiAuthentication(BaseAuthentication):
    def _get_ip_list(self, uuid=None):
        ip_list = None
        if uuid and f"ip-{uuid}" in cache:
            ip_list = cache.get(f"ip-{uuid}")
        elif uuid:
            try:
                ip_list = OrganizationRadiusSettings.objects.get(
                    organization__pk=uuid
                ).freeradius_allowed_hosts_list
            except OrganizationRadiusSettings.DoesNotExist:
                pass
            else:
                cache.set(f"ip-{uuid}", ip_list)
        return ip_list or app_settings.FREERADIUS_ALLOWED_HOSTS

    def _check_client_ip_and_return(self, request, uuid):
        client_ip, _is_routable = get_client_ip(request)
        ip_list = self._get_ip_list(uuid)

        for ip in ip_list:
            try:
                if ipaddress.ip_address(client_ip) in ipaddress.ip_network(ip):
                    return (AnonymousUser(), uuid)
            except ValueError:
                invalid_addr_message = _(
                    "Request rejected: ({ip}) in organization settings or "
                    "settings.py is not a valid IP address. "
                    "Please contact administrator."
                ).format(ip=ip)
                raise AuthenticationFailed(invalid_addr_message)
        message = _(
            "Request rejected: Client IP address ({client_ip}) is not in "
            "the list of IP addresses allowed to consume the freeradius API."
        ).format(client_ip=client_ip)
        raise AuthenticationFailed(message)

    def _handle_mac_address_authentication(self, username, request):
        if not username or not RE_MAC_ADDR.search(username):
            # Username is either None or not a MAC addresss
            return username, request
        calling_station_id = RE_MAC_ADDR.match(username)[0]
        # Get the most recent open session for the roaming user
        open_session = (
            RadiusAccounting.objects.select_related("organization__radius_settings")
            .filter(calling_station_id=calling_station_id, stop_time=None)
            .order_by("-start_time")
            .first()
        )
        if (
            not open_session
            or not open_session.organization.radius_settings.mac_addr_roaming_enabled
        ):
            return None, None
        username = open_session.username
        if hasattr(request.data, "_mutable"):
            request.data._mutable = True
        request.data["username"] = username
        if hasattr(request.data, "_mutable"):
            request.data._mutable = False
        request._mac_allowed = True
        return username, request

    def _radius_token_authenticate(self, username, request):
        # cached_orgid exists only for users authenticated
        # successfully in past 24 hours
        cached_orgid = cache.get(f"rt-{username}")
        if cached_orgid:
            values = self._check_client_ip_and_return(request, cached_orgid)
            return values
        else:
            try:
                radtoken = RadiusToken.objects.get(
                    user=auth_backend.get_users(username).first()
                )
            except RadiusToken.DoesNotExist:
                if username:
                    message = _(
                        "Radius token does not exist. Obtain a new radius token "
                        "or provide the organization UUID and API token."
                    )
                else:
                    message = _("username field is required.")
                raise NotAuthenticated(message)
            org_uuid = str(radtoken.organization_id)
            cache.set(f"rt-{username}", org_uuid, 86400)
            return self._check_client_ip_and_return(request, org_uuid)

    def authenticate(self, request):
        self.check_organization(request)
        uuid, token = self.get_uuid_token(request)
        if not uuid and not token:
            if request.data.get("status_type", None) in SPECIAL_STATUS_TYPES:
                return self._check_client_ip_and_return(request, uuid)
            username = request.data.get("username") or request.query_params.get(
                "username"
            )
            username, request = self._handle_mac_address_authentication(
                username, request
            )
            if username is None and request is None:
                # When using MAC auth roaming, the "username" attribute contains the MAC
                # address (calling_station_id). When the user connects the first time,
                # since it doesn't have any open session, the mac address authorization
                # will fail, in order to avoid filling the log with failed mac address
                # authorization requests we return "None" here
                # (instead of raising "AuthenticationFailed").
                # freeradius will take care of rejecting the authorization if no
                # explicit "Auth-Type: Accept" is returned
                return
            return self._radius_token_authenticate(username, request)
        if not uuid or not token:
            raise AuthenticationFailed(_TOKEN_AUTH_FAILED)
        # check cache first
        cached_token = cache.get(uuid)
        if not cached_token:
            try:
                opts = dict(organization_id=uuid, token=token)
                instance = OrganizationRadiusSettings.objects.get(**opts)
                cache.set(uuid, instance.token)
            except OrganizationRadiusSettings.DoesNotExist:
                raise AuthenticationFailed(_TOKEN_AUTH_FAILED)
        elif cached_token != token:
            raise AuthenticationFailed(_TOKEN_AUTH_FAILED)
        # if execution gets here the auth token is good
        # we include the organization id in the auth info
        return self._check_client_ip_and_return(request, uuid)

    def check_organization(self, request):
        if "organization" in request.data:
            raise AuthenticationFailed(
                _("setting the organization parameter explicitly is not allowed")
            )

    def get_uuid_token(self, request):
        # default to GET params
        uuid = request.GET.get("uuid")
        token = request.GET.get("token")
        # inspect authorization header
        if "HTTP_AUTHORIZATION" in request.META:
            parts = request.META["HTTP_AUTHORIZATION"].split(" ")
            try:
                uuid = parts[1]
                token = parts[2]
            except IndexError:
                raise ParseError(_("Invalid token"))
        return uuid, token


class AuthorizeView(GenericAPIView, IDVerificationHelper):
    authentication_classes = (FreeradiusApiAuthentication,)
    accept_attributes = {"control:Auth-Type": "Accept"}
    accept_status = 200
    reject_attributes = {"control:Auth-Type": "Reject"}
    reject_status = 401
    # we need to use 200 status code or we risk some NAS to
    # interpret other status codes (eg: 403) as invalid credentials
    # (this happens on PfSense)
    max_quota_status = 200
    max_quota_attributes = {
        "control:Auth-Type": "Reject",
        "Reply-Message": BaseCounter.reply_message,
    }
    serializer_class = AuthorizeSerializer

    @swagger_auto_schema(
        responses={
            accept_status: f"`{accept_attributes}`",
            reject_status: f"`{reject_attributes}`",
            max_quota_status: f"`{max_quota_attributes}`",
        }
    )
    def post(self, request, *args, **kwargs):
        """
        **API Endpoint used by FreeRADIUS server.**
        It's triggered when a user submits the form to login into the captive portal.
        The captive portal has to be configured to send the password to freeradius
        in clear text (will be encrypted with the freeradius shared secret,
        can be tunneled via TLS for increased security if needed). FreeRADIUS in
        turn will send the username and password via HTTPS to this endpoint.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data.get("username")
        password = serializer.validated_data.get("password")
        called_station_id = serializer.validated_data.get("called_station_id")
        calling_station_id = serializer.validated_data.get("calling_station_id")
        user = self.get_user(request, username, password)
        if user and self.authenticate_user(request, user, password):
            data, status = self.get_replies(
                user,
                organization_id=request.auth,
                called_station_id=called_station_id,
                calling_station_id=calling_station_id,
            )
            return Response(data, status=status)
        if app_settings.API_AUTHORIZE_REJECT:
            return Response(self.reject_attributes, status=self.reject_status)
        else:
            return Response(None, status=200)

    def get_user(self, request, username, password):
        """
        return user or ``None``
        """
        conditions = self._get_user_query_conditions(request)
        try:
            user = auth_backend.get_users(username).filter(conditions)[0]
        except IndexError:
            return None
        # ensure user is member of the authenticated org
        # or RadiusToken for the user exists.
        lookup_options = dict(user=user, organization_id=request.auth)
        if (
            RadiusToken.objects.filter(**lookup_options).exists()
            or OrganizationUser.objects.filter(**lookup_options).exists()
        ):
            return user
        return None

    def get_replies(
        self, user, organization_id, called_station_id=None, calling_station_id=None
    ):
        """
        Returns user group replies and executes counter checks
        """
        data = self.accept_attributes.copy()
        user_group = get_user_group(user, organization_id)

        if user_group:
            # Use utility function to get group replies
            group_replies = get_group_replies(user_group.group)
            data.update(group_replies)

            group_checks = get_group_checks(user_group.group)

            # Validate simultaneous use
            simultaneous_use = self._check_simultaneous_use(
                data,
                user,
                group_checks,
                organization_id,
                called_station_id=called_station_id,
                calling_station_id=calling_station_id,
            )
            if simultaneous_use is not None:
                return simultaneous_use

            # Execute counter checks
            counter_result = self._check_counters(
                data, user, user_group.group, group_checks
            )
            if counter_result is not None:
                return counter_result

        return data, self.accept_status

    def _check_simultaneous_use(
        self,
        data,
        user,
        group_checks,
        organization_id,
        called_station_id=None,
        calling_station_id=None,
    ):
        """
        Check if user has exceeded simultaneous use limit

        Returns rejection response if limit is exceeded
        """
        if (check := group_checks.get("Simultaneous-Use")) is None or (
            max_simultaneous := int(check.value)
        ) <= 0:
            # Exit early if the `Simultaneous-Use` check is not defined
            # in the RadiusGroup or if it permits unlimited concurrent sessions.
            return None

        open_sessions = RadiusAccounting.objects.filter(
            username=user.username,
            organization_id=organization_id,
            stop_time__isnull=True,
        )
        # In some corner cases, RADIUS accounting sessions
        # can remain open even though the user is not authenticated
        # on the NAS anymore, for this reason, we shall allow re-authentication
        # of the same client on the same NAS.
        if called_station_id and calling_station_id:
            open_sessions = open_sessions.exclude(
                called_station_id=called_station_id,
                calling_station_id=calling_station_id,
            )
        open_sessions = open_sessions.count()
        if open_sessions >= max_simultaneous:
            data.update(self.reject_attributes.copy())
            if "Reply-Message" not in data:
                data["Reply-Message"] = "You are already logged in - access denied"
            return data, self.reject_status

    def _check_counters(self, data, user, group, group_checks):
        """
        Execute counter checks and return rejection response if any quota is exceeded
        Returns None if all checks pass
        """
        try:
            counter_replies = execute_counter_checks(
                user, group, group_checks, existing_replies=data
            )
            # Merge counter replies into data
            data.update(counter_replies)
        except MaxQuotaReached as max_quota:
            # if max is reached send access rejected + reply message
            data.update(self.reject_attributes.copy())
            if "Reply-Message" not in data:
                data["Reply-Message"] = max_quota.reply_message
            return data, self.max_quota_status

        return None

    def _get_user_query_conditions(self, request):
        is_active = Q(is_active=True)
        needs_verification = self._needs_identity_verification({"pk": request._auth})
        # if no identity verification enabled for this org,
        # just ensure user is active
        if not needs_verification:
            return is_active
        # if identity verification is enabled
        is_verified = Q(registered_user__is_verified=True)
        AUTHORIZE_UNVERIFIED = registration.AUTHORIZE_UNVERIFIED
        # and no method should authorize unverified users
        # ensure user is active AND verified
        if not AUTHORIZE_UNVERIFIED:
            return is_active & is_verified
        # in case some methods are allowed to authorize unverified users
        # ensure user is active AND
        # (user is verified OR user uses one of these methods)
        else:
            authorize_unverified = Q(registered_user__method__in=AUTHORIZE_UNVERIFIED)
            return is_active & (is_verified | authorize_unverified)

    def authenticate_user(self, request, user, password):
        """
        returns ``True`` if the password value supplied is
        a valid user password or a valid user token
        can be overridden to implement more complex checks
        """
        return bool(
            getattr(request, "_mac_allowed", False)
            or (
                not user.has_password_expired()
                and (
                    user.check_password(password)
                    or self.check_user_token(request, user, password)
                )
            )
        )

    def check_user_token(self, request, user, password):
        """
        returns ``True`` if the password value supplied is a valid
        radius user token
        """
        try:
            token = RadiusToken.objects.get(
                user=user,
                can_auth=True,
                key=password,
                organization_id=self.request.auth,
            )
        except RadiusToken.DoesNotExist:
            return False
        if app_settings.DISPOSABLE_RADIUS_USER_TOKEN:
            token.can_auth = False
            token.save()
        return True


authorize = AuthorizeView.as_view()


class AccountingViewPagination(drf_link_header_pagination.LinkHeaderPagination):
    page_size = 10
    page_size_query_param = "page_size"
    max_page_size = 100


class AccountingView(ListCreateAPIView):
    """
    HEADER: Pagination is provided using a Link header
            https://developer.github.com/v3/guides/traversing-with-pagination/

    GET: get list of accounting objects

    POST: add or update accounting information (start, interim-update, stop);
          does not return any JSON response so that freeradius will avoid
          processing the response without generating warnings
    """

    throttle_scope = "accounting"
    queryset = RadiusAccounting.objects.all().order_by("-start_time")
    authentication_classes = (FreeradiusApiAuthentication,)
    serializer_class = RadiusAccountingSerializer
    pagination_class = AccountingViewPagination
    filter_backends = (DjangoFilterBackend,)
    filterset_class = AccountingFilter

    def get_queryset(self):
        return super().get_queryset().filter(organization_id=self.request.auth)

    def get(self, request, *args, **kwargs):
        """
        **API Endpoint used by FreeRADIUS server.**
        Returns a list of accounting objects
        """
        return super().get(self, request, *args, **kwargs)

    @swagger_auto_schema(responses={201: "", 200: ""})
    def post(self, request, *args, **kwargs):
        """
        **API Endpoint used by FreeRADIUS server.**
        Add or update accounting information (start, interim-update, stop);
        does not return any JSON response so that freeradius will avoid
        processing the response without generating warnings
        """
        data = request.data.copy()
        status_type = data.get("status_type", None)
        # Special Cases
        if (
            request.user.is_anonymous and request.auth is None
        ) or status_type in SPECIAL_STATUS_TYPES:
            if status_type == "Accounting-On":
                self._handle_accounting_on(data)
            return Response(status=status.HTTP_200_OK)
        # Create or Update
        try:
            instance = self.get_queryset().get(unique_id=data.get("unique_id"))
        except RadiusAccounting.DoesNotExist:
            serializer = self.get_serializer(data=data)
            try:
                serializer.is_valid(raise_exception=True)
            except ValidationError as error:
                if self._is_interim_update_corner_case(error, data):
                    return Response(status=status.HTTP_200_OK)
                raise error
            acct_data = self._data_to_acct_model(serializer.validated_data.copy())
            try:
                serializer.create(acct_data)
            # on large systems using mac auth roaming this could happen
            except IntegrityError:
                logger.info(f"Ignoring duplicate session {acct_data}")
                return Response(status=status.HTTP_200_OK)
            headers = self.get_success_headers(serializer.data)
            self.send_radius_accounting_signal(serializer.validated_data)
            return Response(status=status.HTTP_201_CREATED, headers=headers)
        else:
            serializer = self.get_serializer(instance, data=data, partial=False)
            serializer.is_valid(raise_exception=True)
            acct_data = self._data_to_acct_model(serializer.validated_data.copy())
            serializer.update(instance, acct_data)
            self.send_radius_accounting_signal(serializer.validated_data)
            return Response(status=status.HTTP_200_OK)

    def _handle_accounting_on(self, data):
        """
        When NAS devices are cold rebooted,
        they may not close active sessions,
        which can cause issues with Simultaneous-Use.
        For this reason, OpenWISP closes any open session from
        the same NAS when it receives an Accounting-On request.
        """
        called_station_id = data.get("called_station_id")
        closed_count = RadiusAccounting._close_stale_sessions_on_nas_boot(
            called_station_id=called_station_id
        )
        if closed_count:
            logger.info(
                f"Closed {closed_count} stale session(s) for device with "
                f"Called-Station-Id {called_station_id} in organization "
                f"{self.request.auth} due to receiving an "
                "Accounting-On packet."
            )

    def _is_interim_update_corner_case(self, error, data):
        """
        Handles "Interim-Updates" for RadiusAccounting sessions
        that are closed by OpenWISP when user logs into
        another organization.
        """
        unique_id_errors = error.detail.get("unique_id", [])
        if len(unique_id_errors) == 1:
            error_detail = unique_id_errors.pop()
            if (
                str(error_detail)
                == "accounting with this accounting unique ID already exists."
                and error_detail.code == "unique"
            ):
                rad = RadiusAccounting.objects.only("organization_id").get(
                    unique_id=data.get("unique_id")
                )
                if rad.organization_id != self.request.auth:
                    return True
        return False

    def _data_to_acct_model(self, valid_data):
        acct_org = Organization.objects.get(pk=self.request.auth)
        valid_data.pop("status_type", None)
        valid_data["organization"] = acct_org
        return valid_data

    def send_radius_accounting_signal(self, accounting_data):
        radius_accounting_success.send(
            sender=self.__class__,
            accounting_data=accounting_data,
            view=self,
        )


accounting = AccountingView.as_view()


class PostAuthView(CreateAPIView):
    authentication_classes = (FreeradiusApiAuthentication,)
    serializer_class = RadiusPostAuthSerializer

    @swagger_auto_schema(responses={201: ""})
    def post(self, request, *args, **kwargs):
        """
        **API Endpoint used by FreeRADIUS server.**
        Returns an empty response body in order to instruct
        FreeRADIUS to avoid processing the response body.
        """
        if request.user.is_anonymous and request.auth is None:
            return Response(status=status.HTTP_200_OK)
        response = super().post(request, *args, **kwargs)
        response.data = None
        return response

    def perform_create(self, serializer):
        organization = Organization.objects.get(pk=self.request.auth)
        serializer.save(organization=organization)


postauth = PostAuthView.as_view()
