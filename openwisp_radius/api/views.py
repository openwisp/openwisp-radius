import logging
from uuid import UUID

import drf_link_header_pagination
import swapper
from allauth.account import app_settings as allauth_settings
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.http import Http404, HttpResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django_filters import rest_framework as filters
from django_filters.rest_framework import DjangoFilterBackend
from rest_auth import app_settings as rest_auth_settings
from rest_auth.app_settings import JWTSerializer, TokenSerializer
from rest_auth.registration.views import RegisterView as BaseRegisterView
from rest_auth.views import PasswordChangeView as BasePasswordChangeView
from rest_auth.views import PasswordResetConfirmView as BasePasswordResetConfirmView
from rest_auth.views import PasswordResetView as BasePasswordResetView
from rest_framework import generics, serializers, status
from rest_framework.authentication import BaseAuthentication, SessionAuthentication
from rest_framework.authentication import TokenAuthentication as UserTokenAuthentication
from rest_framework.authtoken.models import Token as UserToken
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.authtoken.views import ObtainAuthToken as BaseObtainAuthToken
from rest_framework.exceptions import AuthenticationFailed, NotFound, ParseError
from rest_framework.exceptions import ValidationError as RestValidationError
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.permissions import (
    DjangoModelPermissions,
    IsAdminUser,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle  # get_ident method
from rest_framework.views import APIView

from openwisp_users.api.authentication import BearerAuthentication

from .. import settings as app_settings
from ..exceptions import PhoneTokenException
from ..utils import generate_pdf, load_model
from .serializers import (
    ChangePhoneNumberSerializer,
    RadiusAccountingSerializer,
    RadiusBatchSerializer,
    RadiusPostAuthSerializer,
    ValidatePhoneTokenSerializer,
)
from .utils import ErrorDictMixin

_TOKEN_AUTH_FAILED = _('Token authentication failed')
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


class TokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        self.check_organization(request)
        uuid, token = self.get_uuid_token(request)
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
        return (AnonymousUser(), uuid)

    def check_organization(self, request):
        if 'organization' in request.data:
            raise AuthenticationFailed(
                _('setting the organization parameter ' 'explicitly is not allowed')
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
                raise ParseError('Invalid token')
        return uuid, token


class TokenAuthorizationMixin(object):
    authentication_classes = (TokenAuthentication,)

    def get_serializer(self, *args, **kwargs):
        # supply organization uuid got from authentication
        if 'data' in kwargs:
            # request.data is immutable so we'll use a normal dict
            data = kwargs['data'].copy()
            data['organization'] = self.request.auth
            kwargs['data'] = data
        return super().get_serializer(*args, **kwargs)


class AuthorizeView(TokenAuthorizationMixin, APIView):
    authentication_classes = (TokenAuthentication,)
    accept_attributes = {'control:Auth-Type': 'Accept'}
    accept_status = 200
    reject_attributes = {'control:Auth-Type': 'Reject'}
    reject_status = 401

    def post(self, request, *args, **kwargs):
        user = self.get_user(request)
        if user and self.authenticate_user(request, user):
            return Response(self.accept_attributes, status=self.accept_status)
        if app_settings.API_AUTHORIZE_REJECT:
            return Response(self.reject_attributes, status=self.reject_status)
        else:
            return Response(None, status=200)

    def get_user(self, request):
        """
        return active user or ``None``
        """
        try:
            user = User.objects.get(
                username=request.data.get('username'), is_active=True
            )
            # ensure user is member of the authenticated org
            if not OrganizationUser.objects.filter(
                user=user, organization_id=request.auth
            ).exists():
                return None
            return user
        except User.DoesNotExist:
            return None

    def authenticate_user(self, request, user):
        """
        returns ``True`` if the password value supplied is
        a valid user password or a valid user token
        can be overridden to implement more complex checks
        """
        return user.check_password(
            request.data.get('password')
        ) or self.check_user_token(
            request, user
        )  # noqa

    def check_user_token(self, request, user):
        """
        returns ``True`` if the password value supplied is a valid
        radius user token
        """

        try:
            token = RadiusToken.objects.get(user=user, key=request.data.get('password'))
        except RadiusToken.DoesNotExist:
            token = None
        if app_settings.DISPOSABLE_RADIUS_USER_TOKEN and token is not None:
            token.delete()
        return token is not None

    def get_serializer(self, *args, **kwargs):
        # needed to avoid `'super' object has no attribute 'get_serializer'`
        # exception, raised in TokenAuthorizationMixin.get_serializer
        return serializers.Serializer(*args, **kwargs)


authorize = AuthorizeView.as_view()


class PostAuthView(TokenAuthorizationMixin, generics.CreateAPIView):
    authentication_classes = (TokenAuthentication,)
    serializer_class = RadiusPostAuthSerializer

    def post(self, request, *args, **kwargs):
        """
        Sets the response data to None in order to instruct
        FreeRADIUS to avoid processing the response body
        """
        response = super().post(request, *args, **kwargs)
        response.data = None
        return response


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


class AccountingView(TokenAuthorizationMixin, generics.ListCreateAPIView):
    """
    HEADER: Pagination is provided using a Link header
            https://developer.github.com/v3/guides/traversing-with-pagination/

    GET: get list of accounting objects

    POST: add or update accounting information (start, interim-update, stop);
          does not return any JSON response so that freeradius will avoid
          processing the response without generating warnings
    """

    authentication_classes = (TokenAuthentication,)
    queryset = RadiusAccounting.objects.all().order_by('-start_time')
    serializer_class = RadiusAccountingSerializer
    pagination_class = AccountingViewPagination
    filter_backends = (DjangoFilterBackend,)
    filter_class = AccountingFilter

    def post(self, request, *args, **kwargs):
        status_type = self._get_status_type(request)
        # Accounting-On and Accounting-Off are not implemented and
        # hence  ignored right now - may be implemented in the future
        if status_type in ['Accounting-On', 'Accounting-Off']:
            return Response(None)
        method = 'create' if status_type == 'Start' else 'update'
        return getattr(self, method)(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        is_start = request.data['status_type'] == 'Start'
        data = request.data.copy()  # import because request objects is immutable
        for field in ['session_time', 'input_octets', 'output_octets']:
            if is_start and request.data[field] == "":
                data[field] = 0
        serializer = self.get_serializer(data=data)
        serializer.is_valid()
        error_keys = serializer.errors.keys()
        errors = len(error_keys)
        if not errors:
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(None, status=201, headers=headers)
        # trying to create a record which
        # already exist, fallback to update
        if errors == 1 and 'unique_id' in error_keys:
            return self.update(request, *args, **kwargs)
        else:
            raise RestValidationError(serializer.errors)

    def perform_create(self, serializer):
        if app_settings.API_ACCOUNTING_AUTO_GROUP:
            user_model = get_user_model()
            username = serializer.validated_data.get('username', "")
            try:
                user = user_model.objects.get(username=username)
            except User.DoesNotExist:
                logging.info(
                    'no corresponding user found ' 'for username: {}'.format(username)
                )
                serializer.save()
            else:
                group = user.radiususergroup_set.order_by('priority').first()
                # user may not have a group defined
                groupname = group.groupname if group else None
                serializer.save(groupname=groupname)
        else:
            return super().perform_create(serializer)

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_queryset().get(unique_id=request.data['unique_id'])
        # trying to update a record which
        # does not exist, fallback to create
        except RadiusAccounting.DoesNotExist:
            return self.create(request, *args, **kwargs)
        serializer = self.get_serializer(instance, data=request.data, partial=False)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(None)

    def _get_status_type(self, request):
        try:
            return request.data['status_type']
        except KeyError:
            raise RestValidationError({'status_type': [_('This field is required.')]})

    def get_queryset(self):
        return super().get_queryset().filter(organization=self.request.auth)


accounting = AccountingView.as_view()


class DispatchOrgMixin(object):
    def dispatch(self, *args, **kwargs):
        try:
            self.organization = Organization.objects.get(slug=kwargs['slug'])
        except Organization.DoesNotExist:
            raise Http404()
        return super().dispatch(*args, **kwargs)

    def validate_membership(self, user):
        if not (user.is_superuser or user.is_member(self.organization)):
            message = _(
                f'User {user.username} is not member of '
                f'organization {self.organization.slug}'
            )
            logger.warning(message)
            raise serializers.ValidationError({'non_field_errors': [message]})


class BatchView(DispatchOrgMixin, generics.CreateAPIView):
    authentication_classes = (BearerAuthentication,)
    permission_classes = (IsAdminUser, DjangoModelPermissions)
    queryset = RadiusBatch.objects.all()
    serializer_class = RadiusBatchSerializer

    def post(self, request, *args, **kwargs):
        self.validate_membership(request.user)
        data = request.data.copy()
        data.update(organization=self.organization.pk)
        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            name = serializer.data.get('name')
            expiration_date = serializer.data.get('expiration_data')
            strategy = serializer.data.get('strategy')
            if strategy == 'csv':
                csvfile = request.FILES['csvfile']
                options = dict(
                    name=name,
                    strategy=strategy,
                    expiration_date=expiration_date,
                    csvfile=csvfile,
                    organization=self.organization,
                )
                batch = RadiusBatch(**options)
                batch.csvfile_upload(csvfile)
                response = RadiusBatchSerializer(batch)
            elif strategy == 'prefix':
                prefix = serializer.data.get('prefix')
                options = dict(
                    name=name,
                    strategy=strategy,
                    expiration_date=expiration_date,
                    prefix=prefix,
                    organization=self.organization,
                )
                batch = RadiusBatch(**options)
                number_of_users = int(request.data['number_of_users'])
                batch.prefix_add(prefix, number_of_users)
                response = RadiusBatchSerializer(batch, context={'request': request})
            return Response(response.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


batch = BatchView.as_view()


class DownloadRadiusBatchPdfView(DispatchOrgMixin, APIView):
    authentication_classes = (UserTokenAuthentication, SessionAuthentication)
    permission_classes = (IsAdminUser, DjangoModelPermissions)
    queryset = RadiusBatch.objects.all()

    def get(self, request, *args, **kwargs):
        self.validate_membership(request.user)
        try:
            radbatch = RadiusBatch.objects.get(pk=kwargs['radbatch'])
        except RadiusBatch.DoesNotExist:
            raise NotFound(
                detail="Given radius batch not found.", code=404,
            )
        if radbatch.strategy == 'prefix':
            pdf = generate_pdf(kwargs['radbatch'])
            response = HttpResponse(content_type='application/pdf')
            response[
                'Content-Disposition'
            ] = f'attachment; filename="{radbatch.name}.pdf"'
            response.write(pdf)
            return response
        else:
            raise NotFound(
                detail="Only available for users created with prefix strategy",
                code=404,
            )


download_rad_batch_pdf = DownloadRadiusBatchPdfView.as_view()


class RadiusTokenMixin(object):
    def get_or_create_radius_token(self, user):
        radius_token, _ = RadiusToken.objects.get_or_create(user=user)
        return radius_token

    def update_user_last_login(self, user):
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])


class RegisterView(RadiusTokenMixin, DispatchOrgMixin, BaseRegisterView):
    authentication_classes = tuple()

    def get_response_data(self, user):
        if (
            allauth_settings.EMAIL_VERIFICATION
            == allauth_settings.EmailVerificationMethod.MANDATORY
        ):
            return {'detail': _('Verification e-mail sent.')}

        context = self.get_serializer_context()

        if getattr(settings, 'REST_USE_JWT', False):
            data = JWTSerializer(
                {'user': user, 'token': self.token}, context=context
            ).data
        else:
            data = TokenSerializer(user.auth_token, context=context).data

        radius_token = self.get_or_create_radius_token(user)
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

    def post(self, request, *args, **kwargs):
        serializer = self.auth_serializer_class(
            data=request.data, context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        user = self.get_user(serializer, *args, **kwargs)
        token, created = UserToken.objects.get_or_create(user=user)
        radius_token = self.get_or_create_radius_token(user)
        self.update_user_last_login(user)
        context = {'view': self, 'request': request, 'token_login': True}
        serializer = self.serializer_class(instance=token, context=context)
        response = {'radius_user_token': radius_token.key}
        response.update(serializer.data)
        return Response(response)

    def get_user(self, serializer, *args, **kwargs):
        user = serializer.validated_data['user']
        self.validate_membership(user)
        return user


obtain_auth_token = ObtainAuthTokenView.as_view()


class ValidateTokenSerializer(serializers.Serializer):
    token = serializers.CharField()


class ValidateAuthTokenView(DispatchOrgMixin, RadiusTokenMixin, generics.CreateAPIView):
    serializer_class = ValidateTokenSerializer

    def post(self, request, *args, **kwargs):
        request_token = request.data.get('token')
        response = {'response_code': 'BLANK_OR_INVALID_TOKEN'}
        if request_token:
            try:
                token = UserToken.objects.select_related('user').get(key=request_token)
                radius_token = self.get_or_create_radius_token(token.user)
                response = {
                    'response_code': 'AUTH_TOKEN_VALIDATION_SUCCESSFUL',
                    'auth_token': token.key,
                    'radius_user_token': radius_token.key,
                    'username': radius_token.user.username,
                }
                self.update_user_last_login(token.user)
                return Response(response, 200)
            except UserToken.DoesNotExist:
                pass
        return Response(response, 401)


validate_auth_token = ValidateAuthTokenView.as_view()


class UserAccountingFilter(AccountingFilter):
    class Meta(AccountingFilter.Meta):
        fields = [
            field for field in AccountingFilter.Meta.fields if field != 'username'
        ]


class UserAccountingView(DispatchOrgMixin, generics.ListAPIView):
    authentication_classes = (UserTokenAuthentication, SessionAuthentication)
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
        return (
            super()
            .get_queryset()
            .filter(organization=self.organization, username=self.request.user.username)
        )


user_accounting = UserAccountingView.as_view()


class PasswordChangeView(DispatchOrgMixin, BasePasswordChangeView):
    authentication_classes = (UserTokenAuthentication,)

    def post(self, request, *args, **kwargs):
        self.validate_membership(request.user)
        return super().post(request, *args, **kwargs)


password_change = PasswordChangeView.as_view()


class PasswordResetView(DispatchOrgMixin, BasePasswordResetView):
    authentication_classes = tuple()

    def post(self, request, *args, **kwargs):
        request.user = self.get_user(request)
        return super().post(request, *args, **kwargs)

    def get_serializer_context(self):
        user = self.request.user
        if not user.pk:
            return
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        # until django 2.1 urlsafe_base64_encode returned a bytestring
        if not isinstance(uid, str):  # noqa
            uid = uid.decode()
        token = default_token_generator.make_token(user)
        password_reset_urls = app_settings.PASSWORD_RESET_URLS
        default_url = password_reset_urls.get('default')
        password_reset_url = password_reset_urls.get(
            str(self.organization.pk), default_url
        )
        password_reset_url = password_reset_url.format(
            organization=self.organization.slug, uid=uid, token=token
        )
        context = {'request': self.request, 'password_reset_url': password_reset_url}
        return context

    def get_user(self, request):
        if request.POST.get('email', None):
            email = request.POST['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise Http404()
            self.validate_membership(user)
            return user
        raise ParseError('email field is required')


password_reset = PasswordResetView.as_view()


class PasswordResetConfirmView(DispatchOrgMixin, BasePasswordResetConfirmView):
    authentication_classes = tuple()

    def post(self, request, *args, **kwargs):
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


class InactiveUserTokenAuthentication(UserTokenAuthentication):
    """
    Overrides the default User Token Authentication
    of Django REST Framework to allow inactive users
    to authenticate against some specific API endpoints.
    """

    def authenticate_credentials(self, key):
        try:
            token = UserToken.objects.select_related('user').get(key=key)
        except UserToken.DoesNotExist:
            raise AuthenticationFailed(_('Invalid token.'))
        else:
            return (token.user, token)


class CreatePhoneTokenView(
    ErrorDictMixin, BaseThrottle, DispatchOrgMixin, CreateAPIView
):
    authentication_classes = (InactiveUserTokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = serializers.Serializer

    def create(self, *args, **kwargs):
        request = self.request
        self.validate_membership(request.user)
        phone_token = PhoneToken(user=request.user, ip=self.get_ident(request))
        try:
            phone_token.full_clean()
        except ValidationError as e:
            error_dict = self._get_error_dict(e)
            raise serializers.ValidationError(error_dict)
        phone_token.save()
        return Response(None, status=201)


create_phone_token = CreatePhoneTokenView.as_view()


class ValidatePhoneTokenView(DispatchOrgMixin, GenericAPIView):
    authentication_classes = (InactiveUserTokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = ValidatePhoneTokenSerializer

    def _error_response(self, message, key='non_field_errors', status=400):
        return Response({key: [message]}, status=status)

    def post(self, request, *args, **kwargs):
        user = request.user
        self.validate_membership(user)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone_token = PhoneToken.objects.filter(user=user).order_by('-created').first()
        if not phone_token:
            return self._error_response(
                _('No verification code found in ' 'the system for this user.')
            )
        try:
            is_valid = phone_token.is_valid(serializer.data['code'])
        except PhoneTokenException as e:
            return self._error_response(str(e))
        if not is_valid:
            return self._error_response(_('Invalid code.'))
        else:
            user.is_active = True
            user.save()
            return Response(None, status=200)


validate_phone_token = ValidatePhoneTokenView.as_view()


class ChangePhoneNumberView(CreatePhoneTokenView):
    authentication_classes = (InactiveUserTokenAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePhoneNumberSerializer

    def create(self, *args, **kwargs):
        serializer = self.get_serializer(
            data=self.request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        # attempt to create the phone token before
        # the new number is saved, so that if the
        # creation of the phone token fails, the
        # phone number remains unchanged
        self.create_phone_token(*args, **kwargs)
        serializer.save()
        return Response(None, status=200)

    def create_phone_token(self, *args, **kwargs):
        return super().create(*args, **kwargs)


change_phone_number = ChangePhoneNumberView.as_view()
