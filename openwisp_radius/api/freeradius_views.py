import ipaddress
import logging
import math

import drf_link_header_pagination
import swapper
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.db.models import Q
from django.utils.translation import gettext_lazy as _
from django_filters import rest_framework as filters
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema
from ipware import get_client_ip
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated, ParseError
from rest_framework.generics import CreateAPIView, GenericAPIView, ListCreateAPIView
from rest_framework.response import Response

from openwisp_users.backends import UsersAuthenticationBackend

from .. import registration
from .. import settings as app_settings
from ..counters.base import BaseCounter
from ..counters.exceptions import MaxQuotaReached, SkipCheck
from ..signals import radius_accounting_success
from ..utils import load_model
from .serializers import (
    AuthorizeSerializer,
    RadiusAccountingSerializer,
    RadiusPostAuthSerializer,
)
from .utils import IDVerificationHelper

_TOKEN_AUTH_FAILED = _('Token authentication failed')
# Accounting-On and Accounting-Off are not implemented and
# hence  ignored right now - may be implemented in the future
UNSUPPORTED_STATUS_TYPES = ['Accounting-On', 'Accounting-Off']
logger = logging.getLogger(__name__)

RadiusToken = load_model('RadiusToken')
RadiusAccounting = load_model('RadiusAccounting')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
Organization = swapper.load_model('openwisp_users', 'Organization')
auth_backend = UsersAuthenticationBackend()


# Radius Accounting
class AccountingFilter(filters.FilterSet):
    start_time = filters.DateTimeFilter(field_name='start_time', lookup_expr='gte')
    stop_time = filters.DateTimeFilter(field_name='stop_time', lookup_expr='lte')
    is_open = filters.BooleanFilter(
        field_name='stop_time', lookup_expr='isnull', label='Is Open'
    )

    class Meta:
        model = RadiusAccounting
        fields = (
            'username',
            'called_station_id',
            'calling_station_id',
            'start_time',
            'stop_time',
            'is_open',
        )


class FreeradiusApiAuthentication(BaseAuthentication):
    def _get_ip_list(self, uuid):
        if f'ip-{uuid}' in cache:
            ip_list = cache.get(f'ip-{uuid}')
        else:
            try:
                ip_list = OrganizationRadiusSettings.objects.get(
                    organization__pk=uuid
                ).freeradius_allowed_hosts_list
            except OrganizationRadiusSettings.DoesNotExist:
                ip_list = None
            else:
                cache.set(f'ip-{uuid}', ip_list)
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
                    'Request rejected: ({ip}) in organization settings or '
                    'settings.py is not a valid IP address. '
                    'Please contact administrator.'
                ).format(ip=ip)
                logger.warning(invalid_addr_message)
                raise AuthenticationFailed(invalid_addr_message)
        message = _(
            'Request rejected: Client IP address ({client_ip}) is not in '
            'the list of IP addresses allowed to consume the freeradius API.'
        ).format(client_ip=client_ip)
        logger.warning(message)
        raise AuthenticationFailed(message)

    def _radius_token_authenticate(self, request):
        if request.data.get('status_type', None) in UNSUPPORTED_STATUS_TYPES:
            return
        # cached_orgid exists only for users authenticated
        # successfully in past 24 hours
        username = request.data.get('username') or request.query_params.get('username')
        cached_orgid = cache.get(f'rt-{username}')
        if cached_orgid:
            return self._check_client_ip_and_return(request, cached_orgid)
        else:
            try:
                radtoken = RadiusToken.objects.get(
                    user=auth_backend.get_users(username).first()
                )
            except RadiusToken.DoesNotExist:
                if username:
                    message = _(
                        'Radius token does not exist. Obtain a new radius token '
                        'or provide the organization UUID and API token.'
                    )
                else:
                    message = _('username field is required.')
                logger.warning(message)
                raise NotAuthenticated(message)
            org_uuid = str(radtoken.organization_id)
            cache.set(f'rt-{username}', org_uuid, 86400)
            return self._check_client_ip_and_return(request, org_uuid)

    def authenticate(self, request):
        self.check_organization(request)
        uuid, token = self.get_uuid_token(request)
        if not uuid and not token:
            return self._radius_token_authenticate(request)
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
        if 'organization' in request.data:
            raise AuthenticationFailed(
                _('setting the organization parameter explicitly is not allowed')
            )

    def get_uuid_token(self, request):
        # default to GET params
        uuid = request.GET.get('uuid')
        token = request.GET.get('token')
        # inspect authorization header
        if 'HTTP_AUTHORIZATION' in request.META:
            parts = request.META['HTTP_AUTHORIZATION'].split(' ')
            try:
                uuid = parts[1]
                token = parts[2]
            except IndexError:
                raise ParseError(_('Invalid token'))
        return uuid, token


class AuthorizeView(GenericAPIView, IDVerificationHelper):
    authentication_classes = (FreeradiusApiAuthentication,)
    accept_attributes = {'control:Auth-Type': 'Accept'}
    accept_status = 200
    reject_attributes = {'control:Auth-Type': 'Reject'}
    reject_status = 401
    # we need to use 200 status code or we risk some NAS to
    # interpret other status codes (eg: 403) as invalid credentials
    # (this happens on PfSense)
    max_quota_status = 200
    max_quota_attributes = {
        'control:Auth-Type': 'Reject',
        'Reply-Message': BaseCounter.reply_message,
    }
    serializer_class = AuthorizeSerializer

    @swagger_auto_schema(
        responses={
            accept_status: f'`{accept_attributes}`',
            reject_status: f'`{reject_attributes}`',
            max_quota_status: f'`{max_quota_attributes}`',
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
        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')
        user = self.get_user(request, username)
        if user and self.authenticate_user(request, user, password):
            data, status = self.get_replies(user, organization_id=request.auth)
            return Response(data, status=status)
        if app_settings.API_AUTHORIZE_REJECT:
            return Response(self.reject_attributes, status=self.reject_status)
        else:
            return Response(None, status=200)

    def get_user(self, request, username):
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

    def get_replies(self, user, organization_id):
        """
        Returns user group replies and executes counter checks
        """
        data = self.accept_attributes.copy()
        user_group = self.get_user_group(user, organization_id)

        if user_group:
            for reply in self.get_group_replies(user_group.group):
                data.update({reply.attribute: {'op': reply.op, 'value': reply.value}})

            group_checks = self.get_group_checks(user_group.group)

            for counter in app_settings.COUNTERS:
                group_check = group_checks.get(counter.check_name)
                try:
                    remaining = counter(
                        user=user, group=user_group.group, group_check=group_check
                    ).check()
                except SkipCheck:
                    continue
                # if max is reached send access rejected + reply message
                except MaxQuotaReached as max_quota:
                    data = self.reject_attributes.copy()
                    data['Reply-Message'] = max_quota.reply_message
                    return data, self.max_quota_status
                # avoid crashing on unexpected runtime errors
                except Exception as e:
                    logger.exception(f'Got exception "{e}" while executing {counter}')
                    continue
                # send remaining value in RADIUS reply, if needed.
                # This emulates the implementation of sqlcounter in freeradius
                # which sends the reply message only if the value is smaller
                # than what was defined to a previous reply message
                if counter.reply_name not in data or remaining < self._get_reply_value(
                    data, counter
                ):
                    data[counter.reply_name] = remaining

        return data, self.accept_status

    @staticmethod
    def _get_reply_value(data, counter):
        value = data[counter.reply_name]['value']
        try:
            return int(value)
        except ValueError:
            logger.warning(
                f'{counter.reply_name} value ("{value}") '
                'cannot be converted to integer.'
            )
            return math.inf

    def get_user_group(self, user, organization_id):
        return (
            user.radiususergroup_set.filter(group__organization_id=organization_id)
            .select_related('group')
            .order_by('priority')
            .first()
        )

    def get_group_replies(self, group):
        return group.radiusgroupreply_set.all()

    def get_group_checks(self, group):
        """
        Used to query the DB for group checks only once
        instead of once per each counter in use.
        """
        if not app_settings.COUNTERS:
            return

        check_attributes = []
        for counter in app_settings.COUNTERS:
            check_attributes.append(counter.check_name)

        group_checks = group.radiusgroupcheck_set.filter(attribute__in=check_attributes)
        result = {}
        for group_check in group_checks:
            result[group_check.attribute] = group_check
        return result

    def _get_user_query_conditions(self, request):
        is_active = Q(is_active=True)
        needs_verification = self._needs_identity_verification({'pk': request._auth})
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
            user.check_password(password)
            or self.check_user_token(request, user, password)
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
    page_size_query_param = 'page_size'
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

    throttle_scope = 'accounting'
    queryset = RadiusAccounting.objects.all().order_by('-start_time')
    authentication_classes = (FreeradiusApiAuthentication,)
    serializer_class = RadiusAccountingSerializer
    pagination_class = AccountingViewPagination
    filter_backends = (DjangoFilterBackend,)
    filter_class = AccountingFilter

    def get_queryset(self):
        return super().get_queryset().filter(organization_id=self.request.auth)

    def get(self, request, *args, **kwargs):
        """
        **API Endpoint used by FreeRADIUS server.**
        Returns a list of accounting objects
        """
        return super().get(self, request, *args, **kwargs)

    @swagger_auto_schema(responses={201: '', 200: ''})
    def post(self, request, *args, **kwargs):
        """
        **API Endpoint used by FreeRADIUS server.**
        Add or update accounting information (start, interim-update, stop);
        does not return any JSON response so that freeradius will avoid
        processing the response without generating warnings
        """
        data = request.data.copy()
        if data.get('status_type', None) in UNSUPPORTED_STATUS_TYPES:
            return Response(None)
        # Create or Update
        try:
            instance = self.get_queryset().get(unique_id=data.get('unique_id'))
        except RadiusAccounting.DoesNotExist:
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            acct_data = self._data_to_acct_model(serializer.validated_data.copy())
            serializer.create(acct_data)
            headers = self.get_success_headers(serializer.data)
            self.send_radius_accounting_signal(serializer.validated_data)
            return Response(None, status=201, headers=headers)
        else:
            serializer = self.get_serializer(instance, data=data, partial=False)
            serializer.is_valid(raise_exception=True)
            acct_data = self._data_to_acct_model(serializer.validated_data.copy())
            serializer.update(instance, acct_data)
            self.send_radius_accounting_signal(serializer.validated_data)
            return Response(None)

    def _data_to_acct_model(self, valid_data):
        acct_org = Organization.objects.get(pk=self.request.auth)
        valid_data.pop('status_type', None)
        valid_data['organization'] = acct_org
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

    @swagger_auto_schema(responses={201: ''})
    def post(self, request, *args, **kwargs):
        """
        **API Endpoint used by FreeRADIUS server.**
        Returns an empty response body in order to instruct
        FreeRADIUS to avoid processing the response body.
        """
        response = super().post(request, *args, **kwargs)
        response.data = None
        return response

    def perform_create(self, serializer):
        organization = Organization.objects.get(pk=self.request.auth)
        serializer.save(organization=organization)


postauth = PostAuthView.as_view()
