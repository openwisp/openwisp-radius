import logging
from uuid import UUID

import drf_link_header_pagination
import swapper
from dj_rest_auth import app_settings as rest_auth_settings
from dj_rest_auth.registration.views import RegisterView as BaseRegisterView
from dj_rest_auth.views import PasswordChangeView as BasePasswordChangeView
from dj_rest_auth.views import PasswordResetConfirmView as BasePasswordResetConfirmView
from dj_rest_auth.views import PasswordResetView as BasePasswordResetView
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django_filters import rest_framework as filters
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import no_body, swagger_auto_schema
from ipware import get_client_ip
from rest_framework import serializers, status
from rest_framework.authentication import BaseAuthentication, SessionAuthentication
from rest_framework.authtoken.models import Token as UserToken
from rest_framework.authtoken.views import ObtainAuthToken as BaseObtainAuthToken
from rest_framework.exceptions import (
    AuthenticationFailed,
    NotAuthenticated,
    NotFound,
    ParseError,
)
from rest_framework.generics import (
    CreateAPIView,
    GenericAPIView,
    ListAPIView,
    ListCreateAPIView,
    RetrieveAPIView,
)
from rest_framework.permissions import (
    DjangoModelPermissions,
    IsAdminUser,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle  # get_ident method

from openwisp_users.api.authentication import BearerAuthentication
from openwisp_users.api.permissions import IsOrganizationManager

from .. import settings as app_settings
from ..exceptions import PhoneTokenException
from ..utils import generate_pdf, load_model
from .permissions import IsSmsVerificationEnabled
from .serializers import (
    AuthorizeSerializer,
    AuthTokenSerializer,
    ChangePhoneNumberSerializer,
    RadiusAccountingSerializer,
    RadiusBatchSerializer,
    RadiusPostAuthSerializer,
    ValidatePhoneTokenSerializer,
)
from .swagger import ObtainTokenRequest, ObtainTokenResponse, RegisterResponse
from .utils import ErrorDictMixin

_TOKEN_AUTH_FAILED = _('Token authentication failed')
renew_required = app_settings.DISPOSABLE_RADIUS_USER_TOKEN
logger = logging.getLogger(__name__)

User = get_user_model()
PhoneToken = load_model('PhoneToken')
RadiusToken = load_model('RadiusToken')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
RadiusPostAuth = load_model('RadiusPostAuth')
RadiusAccounting = load_model('RadiusAccounting')
RadiusBatch = load_model('RadiusBatch')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
Organization = swapper.load_model('openwisp_users', 'Organization')


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
        return ip_list

    def _check_client_ip_and_return(self, request, uuid):
        client_ip, _is_routable = get_client_ip(request)
        ip_list = self._get_ip_list(uuid)
        if bool(
            (ip_list and client_ip in ip_list)
            or (not ip_list and client_ip in app_settings.FREERADIUS_ALLOWED_HOSTS)
        ):
            return (AnonymousUser(), uuid)
        message = _(
            f'Request rejected: Client IP address ({client_ip}) is not in '
            'the list of IP addresses allowed to consume the freeradius API.'
        )
        logger.warning(message)
        raise AuthenticationFailed(message)

    def _radius_token_authenticate(self, request):
        # cached_orgid exists only for users authenticated
        # successfully in past 24 hours
        username = request.data.get('username') or request.query_params.get('username')
        cached_orgid = cache.get(f'rt-{username}')
        if cached_orgid:
            return self._check_client_ip_and_return(request, cached_orgid)
        else:
            try:
                radtoken = RadiusToken.objects.get(user__username=username)
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


class AuthorizeView(GenericAPIView):
    authentication_classes = (FreeradiusApiAuthentication,)
    accept_attributes = {'control:Auth-Type': 'Accept'}
    accept_status = 200
    reject_attributes = {'control:Auth-Type': 'Reject'}
    reject_status = 401
    serializer_class = AuthorizeSerializer

    @swagger_auto_schema(
        responses={
            accept_status: f'`{accept_attributes}`',
            reject_status: f'`{reject_attributes}`',
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
            return Response(self.accept_attributes, status=self.accept_status)
        if app_settings.API_AUTHORIZE_REJECT:
            return Response(self.reject_attributes, status=self.reject_status)
        else:
            return Response(None, status=200)

    def get_user(self, request, username):
        """
        return active user or ``None``
        """
        try:
            user = User.objects.get(username=username, is_active=True)
        except User.DoesNotExist:
            return None
        # ensure user is member of the authenticated org
        # or RadiusToken for the user exists.
        if (
            RadiusToken.objects.filter(user=user).exists()
            or OrganizationUser.objects.filter(
                user=user, organization_id=request.auth
            ).exists()
        ):
            return user
        return None

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
            token = RadiusToken.objects.get(user=user, can_auth=True, key=password)
        except RadiusToken.DoesNotExist:
            return False
        if app_settings.DISPOSABLE_RADIUS_USER_TOKEN:
            token.can_auth = False
            token.save()
        return True


authorize = AuthorizeView.as_view()


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

    queryset = RadiusAccounting.objects.all().order_by('-start_time')
    authentication_classes = (FreeradiusApiAuthentication,)
    serializer_class = RadiusAccountingSerializer
    pagination_class = AccountingViewPagination
    filter_backends = (DjangoFilterBackend,)
    filter_class = AccountingFilter

    def get_queryset(self):
        return super().get_queryset().filter(organization=self.request.auth)

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
        # Accounting-On and Accounting-Off are not implemented and
        # hence  ignored right now - may be implemented in the future
        if data.get('status_type', None) in ['Accounting-On', 'Accounting-Off']:
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
            return Response(None, status=201, headers=headers)
        else:
            serializer = self.get_serializer(instance, data=data, partial=False)
            serializer.is_valid(raise_exception=True)
            acct_data = self._data_to_acct_model(serializer.validated_data.copy())
            serializer.update(instance, acct_data)
            return Response(None)

    def _data_to_acct_model(self, valid_data):
        acct_org = Organization.objects.get(pk=self.request.auth)
        valid_data.pop('status_type', None)
        valid_data['organization'] = acct_org
        return valid_data


accounting = AccountingView.as_view()


class BatchView(CreateAPIView):
    authentication_classes = (BearerAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, DjangoModelPermissions)
    queryset = RadiusBatch.objects.all()
    serializer_class = RadiusBatchSerializer

    def post(self, request, *args, **kwargs):
        """
        **Requires the user auth token (Bearer Token).**
        Allows organization administrators to create
        a batch of users using a csv file or generate users
        with a given prefix.
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            valid_data = serializer.validated_data.copy()
            num_of_users = valid_data.pop('number_of_users', None)
            valid_data['organization'] = valid_data.pop('organization_slug', None)
            batch = serializer.create(valid_data)
            strategy = valid_data.get('strategy')
            if strategy == 'csv':
                batch.csvfile_upload()
                response = RadiusBatchSerializer(batch, context={'request': request})
            else:
                batch.prefix_add(valid_data.get('prefix'), num_of_users)
                response = RadiusBatchSerializer(batch, context={'request': request})
            return Response(response.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


batch = BatchView.as_view()


class DispatchOrgMixin(object):
    def dispatch(self, *args, **kwargs):
        try:
            self.organization = Organization.objects.select_related(
                'radius_settings'
            ).get(slug=kwargs['slug'])
        except Organization.DoesNotExist:
            raise Http404('No Organization matches the given query.')
        return super().dispatch(*args, **kwargs)

    def validate_membership(self, user):
        if not (user.is_superuser or user.is_member(self.organization)):
            message = _(
                f'User {user.username} is not member of '
                f'organization {self.organization.slug}.'
            )
            logger.warning(message)
            raise serializers.ValidationError({'non_field_errors': [message]})


class DownloadRadiusBatchPdfView(DispatchOrgMixin, RetrieveAPIView):
    authentication_classes = (BearerAuthentication, SessionAuthentication)
    permission_classes = (IsOrganizationManager, IsAdminUser, DjangoModelPermissions)
    queryset = RadiusBatch.objects.all()

    @swagger_auto_schema(responses={200: '(File Byte Stream)'})
    def get(self, request, *args, **kwargs):
        radbatch = self.get_object()
        if radbatch.strategy == 'prefix':
            pdf = generate_pdf(radbatch.pk)
            response = HttpResponse(content_type='application/pdf')
            response[
                'Content-Disposition'
            ] = f'attachment; filename="{radbatch.name}.pdf"'
            response.write(pdf)
            return response
        else:
            message = _('Only available for users created with prefix strategy')
            raise NotFound(message)


download_rad_batch_pdf = DownloadRadiusBatchPdfView.as_view()


class RadiusTokenMixin(object):
    def _radius_accounting_nas_stop(self, user, organization):
        """
        Flags the last open radius session of the
        specific organization as terminated
        """
        radacct = (
            RadiusAccounting.objects.filter(
                username=user, organization=organization, stop_time=None
            )
            .order_by('start_time')
            .last()
        )
        # nothing to update
        if not radacct:
            return
        # an open session found, flag it as terminated
        radacct.terminate_cause = 'NAS_Request'
        time = timezone.now()
        radacct.update_time = time
        radacct.stop_time = time
        radacct.full_clean()
        radacct.save()

    def _delete_used_token(self, user, organization):
        try:
            used_radtoken = RadiusToken.objects.get(user=user)
        except RadiusToken.DoesNotExist:
            pass
        else:
            # If organization is changed, stop accounting for
            # the previously used for organization
            in_use_org = used_radtoken.organization
            if in_use_org != organization:
                self._radius_accounting_nas_stop(user, in_use_org)
            used_radtoken.delete()

    def get_or_create_radius_token(
        self, user, organization, enable_auth=True, renew=True
    ):
        if renew:
            self._delete_used_token(user, organization)
        try:
            radius_token, _ = RadiusToken.objects.get_or_create(
                user=user, organization=organization
            )
        except IntegrityError:
            radius_token = RadiusToken.objects.get(user=user)
            self._radius_accounting_nas_stop(user, radius_token.organization)
            radius_token.organization = organization
        radius_token.can_auth = enable_auth
        radius_token.full_clean()
        radius_token.save()
        # Create a cache for 24 hours so that next
        # user request is responded quickly.
        if enable_auth:
            cache.set(f'rt-{user.username}', str(organization.pk), 86400)
        return radius_token

    def update_user_last_login(self, user):
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])


@method_decorator(
    name='post',
    decorator=swagger_auto_schema(
        operation_description=(
            'Used by users to create new accounts, usually to access the internet.'
        ),
        responses={201: RegisterResponse},
    ),
)
class RegisterView(RadiusTokenMixin, DispatchOrgMixin, BaseRegisterView):
    authentication_classes = tuple()

    def get_response_data(self, user):
        data = super().get_response_data(user)
        radius_token = self.get_or_create_radius_token(
            user, self.organization, enable_auth=False
        )
        data['radius_user_token'] = radius_token.key
        return data


register = RegisterView.as_view()


class ObtainAuthTokenView(DispatchOrgMixin, RadiusTokenMixin, BaseObtainAuthToken):
    serializer_class = rest_auth_settings.TokenSerializer
    auth_serializer_class = AuthTokenSerializer
    authentication_classes = []

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(ObtainAuthTokenView, self).dispatch(request, *args, **kwargs)

    @swagger_auto_schema(
        request_body=ObtainTokenRequest, responses={200: ObtainTokenResponse}
    )
    def post(self, request, *args, **kwargs):
        """
        Obtain the user radius token required for authentication in APIs.
        """
        serializer = self.auth_serializer_class(
            data=request.data, context={'request': request}
        )
        # import ipdb; ipdb.set_trace()
        serializer.is_valid(raise_exception=True)
        user = self.get_user(serializer, *args, **kwargs)
        token, _ = UserToken.objects.get_or_create(user=user)
        radius_token = self.get_or_create_radius_token(
            user, self.organization, renew=renew_required
        )
        self.update_user_last_login(user)
        context = {'view': self, 'request': request, 'token_login': True}
        serializer = self.serializer_class(instance=token, context=context)
        response = {'radius_user_token': radius_token.key, 'is_active': user.is_active}
        response.update(serializer.data)
        status_code = 200 if user.is_active else 401
        return Response(response, status=status_code)

    def get_user(self, serializer, *args, **kwargs):
        user = serializer.validated_data['user']
        self.validate_membership(user)
        return user


obtain_auth_token = ObtainAuthTokenView.as_view()


class ValidateTokenSerializer(serializers.Serializer):
    token = serializers.CharField()


class ValidateAuthTokenView(DispatchOrgMixin, RadiusTokenMixin, CreateAPIView):
    serializer_class = ValidateTokenSerializer

    def post(self, request, *args, **kwargs):
        """
        Used to check whether the auth token of a user is valid or not.
        """
        request_token = request.data.get('token')
        response = {'response_code': 'BLANK_OR_INVALID_TOKEN'}
        if request_token:
            try:
                token = UserToken.objects.select_related('user').get(key=request_token)
            except UserToken.DoesNotExist:
                pass
            else:
                user = token.user
                radius_token = self.get_or_create_radius_token(
                    user, self.organization, renew=renew_required
                )
                if not user.is_active:
                    phone_token = (
                        PhoneToken.objects.filter(user=user)
                        .order_by('-created')
                        .first()
                    )
                    phone_number = (
                        phone_token.phone_number if phone_token else user.phone_number
                    )
                else:
                    phone_number = user.phone_number
                response = {
                    'response_code': 'AUTH_TOKEN_VALIDATION_SUCCESSFUL',
                    'auth_token': token.key,
                    'radius_user_token': radius_token.key,
                    'username': user.username,
                    'email': user.email,
                    'is_active': user.is_active,
                    'phone_number': str(phone_number),
                }
                self.update_user_last_login(token.user)
                return Response(response, 200)
        return Response(response, 401)


validate_auth_token = ValidateAuthTokenView.as_view()


class UserAccountingFilter(AccountingFilter):
    class Meta(AccountingFilter.Meta):
        fields = [
            field for field in AccountingFilter.Meta.fields if field != 'username'
        ]


@method_decorator(
    name='get',
    decorator=swagger_auto_schema(
        operation_description="""
        **Requires the user auth token (Bearer Token).**
        Returns the radius sessions of the logged-in user and the organization
        specified in the URL.
        """,
    ),
)
class UserAccountingView(DispatchOrgMixin, ListAPIView):
    authentication_classes = (BearerAuthentication, SessionAuthentication)
    permission_classes = (IsAuthenticated,)
    serializer_class = RadiusAccountingSerializer
    pagination_class = AccountingViewPagination
    filter_backends = (DjangoFilterBackend,)
    filter_class = UserAccountingFilter
    queryset = RadiusAccounting.objects.all().order_by('-start_time')

    def list(self, request, *args, **kwargs):
        self.request = request
        return super().list(request, *args, **kwargs)

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return super().get_queryset()  # pragma: no cover
        return (
            super()
            .get_queryset()
            .filter(organization=self.organization, username=self.request.user.username)
        )


user_accounting = UserAccountingView.as_view()


class PasswordChangeView(DispatchOrgMixin, BasePasswordChangeView):
    authentication_classes = (BearerAuthentication,)

    @swagger_auto_schema(responses={200: '`{"detail":"New password has been saved."}`'})
    def post(self, request, *args, **kwargs):
        """
        **Requires the user auth token (Bearer Token).**
        Allows users to change their password after using
        the `Reset password` endpoint.
        """
        self.validate_membership(request.user)
        return super().post(request, *args, **kwargs)


password_change = PasswordChangeView.as_view()


class PasswordResetView(DispatchOrgMixin, BasePasswordResetView):
    authentication_classes = tuple()

    @swagger_auto_schema(
        responses={
            200: '`{"detail": "Password reset e-mail has been sent."}`',
            400: '`{"detail": "email field is required"}`',
            404: '`{"detail": "Not found."}`',
        }
    )
    def post(self, request, *args, **kwargs):
        """
        This is the classic "password forgotten recovery feature" which
        sends a reset password token to the email of the user.
        """
        request.user = self.get_user(request)
        return super().post(request, *args, **kwargs)

    def get_serializer_context(self):
        user = self.request.user
        if not user.pk:
            return
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        password_reset_urls = app_settings.PASSWORD_RESET_URLS
        default_url = password_reset_urls.get('default')
        domain = get_current_site(self.request).domain
        if getattr(self, 'swagger_fake_view', False):
            organization_pk, organization_slug = None, None  # pragma: no cover
        else:
            organization_pk = self.organization.pk
            organization_slug = self.organization.slug
        password_reset_url = password_reset_urls.get(str(organization_pk), default_url)
        password_reset_url = password_reset_url.format(
            organization=organization_slug, uid=uid, token=token, site=domain
        )
        context = {'request': self.request, 'password_reset_url': password_reset_url}
        return context

    def get_user(self, request):
        if request.data.get('email', None):
            email = request.data['email']
            user = get_object_or_404(User, email=email)
            self.validate_membership(user)
            return user
        raise ParseError(_('email field is required'))


password_reset = PasswordResetView.as_view()


class PasswordResetConfirmView(DispatchOrgMixin, BasePasswordResetConfirmView):
    authentication_classes = tuple()

    @swagger_auto_schema(
        responses={
            200: '`{"detail": "Password has been reset with the new password."}`',
        }
    )
    def post(self, request, *args, **kwargs):
        """
        Allows users to confirm their reset password after having
        it requested via the `Reset password` endpoint.
        """
        self.validate_user()
        return super().post(request, *args, **kwargs)

    def validate_user(self, *args, **kwargs):
        if self.request.POST.get('uid', None):
            try:
                uid = force_text(urlsafe_base64_decode(self.request.POST['uid']))
                uid = UUID(str(uid))
                user = User.objects.get(pk=uid)
            except (User.DoesNotExist, ValueError):
                raise Http404()
            self.validate_membership(user)
            return user


password_reset_confirm = PasswordResetConfirmView.as_view()


class InactiveBearerTokenAuthentication(BearerAuthentication):
    """
    Overrides the Bearer Authentication of openwisp-users
    to allow inactive users to authenticate against
    some specific API endpoints.
    """

    def authenticate_credentials(self, key):
        try:
            token = UserToken.objects.select_related('user').get(key=key)
        except UserToken.DoesNotExist:
            raise AuthenticationFailed(_('Invalid token.'))
        else:
            return (token.user, token)


@method_decorator(
    name='post',
    decorator=swagger_auto_schema(
        operation_description=(
            """
            **Requires the user auth token (Bearer Token).**
            Used for SMS verification, sends a code via SMS to the
            phone number of the user.
            """
        ),
        request_body=no_body,
        responses={201: ''},
    ),
)
class CreatePhoneTokenView(
    ErrorDictMixin, BaseThrottle, DispatchOrgMixin, CreateAPIView
):
    authentication_classes = (InactiveBearerTokenAuthentication,)
    permission_classes = (
        IsSmsVerificationEnabled,
        IsAuthenticated,
    )

    def create(self, *args, **kwargs):
        request = self.request
        self.validate_membership(request.user)
        phone_number = request.data.get('phone_number', request.user.phone_number)
        phone_token = PhoneToken(
            user=request.user, ip=self.get_ident(request), phone_number=phone_number,
        )
        try:
            phone_token.full_clean()
        except ValidationError as e:
            error_dict = self._get_error_dict(e)
            raise serializers.ValidationError(error_dict)
        phone_token.save()
        return Response(None, status=201)


create_phone_token = CreatePhoneTokenView.as_view()


class ValidatePhoneTokenView(DispatchOrgMixin, GenericAPIView):
    authentication_classes = (InactiveBearerTokenAuthentication,)
    permission_classes = (
        IsSmsVerificationEnabled,
        IsAuthenticated,
    )
    serializer_class = ValidatePhoneTokenSerializer

    def _error_response(self, message, key='non_field_errors', status=400):
        return Response({key: [message]}, status=status)

    @swagger_auto_schema(responses={201: ''})
    def post(self, request, *args, **kwargs):
        """
        **Requires the user auth token (Bearer Token).**
        Used for SMS verification, allows users to validate the
        code they receive via SMS.
        """
        user = request.user
        self.validate_membership(user)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_token = PhoneToken.objects.filter(user=user).order_by('-created').first()
        if not phone_token:
            return self._error_response(
                _('No verification code found in the system for this user.')
            )
        try:
            is_valid = phone_token.is_valid(serializer.data['code'])
        except PhoneTokenException as e:
            return self._error_response(str(e))
        if not is_valid:
            return self._error_response(_('Invalid code.'))
        else:
            user.is_active = True
            user.phone_number = phone_token.phone_number
            user.save()
            return Response(None, status=200)


validate_phone_token = ValidatePhoneTokenView.as_view()


@method_decorator(
    name='post',
    decorator=swagger_auto_schema(
        operation_description=(
            """
            **Requires the user auth token (Bearer Token).**
            Allows users to change their phone number, will flag the
            user as inactive and send them a verification code via SMS.
            """
        ),
        responses={200: ''},
    ),
)
class ChangePhoneNumberView(CreatePhoneTokenView):
    authentication_classes = (InactiveBearerTokenAuthentication,)
    permission_classes = (
        IsSmsVerificationEnabled,
        IsAuthenticated,
    )
    serializer_class = ChangePhoneNumberSerializer

    def create(self, *args, **kwargs):
        serializer = self.get_serializer(
            data=self.request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        # attempt to create the phone token before
        # the user is marked inactive, so that if the
        # creation of the phone token fails, the
        # the user's is_active state remains unchanged
        self.create_phone_token(*args, **kwargs)
        serializer.save()
        return Response(None, status=200)

    def create_phone_token(self, *args, **kwargs):
        return super().create(*args, **kwargs)


change_phone_number = ChangePhoneNumberView.as_view()
