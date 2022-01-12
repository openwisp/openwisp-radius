import logging

import swapper
from allauth.account.forms import default_token_generator
from allauth.account.utils import url_str_to_user_pk, user_pk_to_url_str
from dj_rest_auth import app_settings as rest_auth_settings
from dj_rest_auth.registration.views import RegisterView as BaseRegisterView
from dj_rest_auth.views import PasswordResetConfirmView as BasePasswordResetConfirmView
from dj_rest_auth.views import PasswordResetView as BasePasswordResetView
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.utils.translation.trans_real import get_language_from_request
from django.views.decorators.csrf import csrf_exempt
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import no_body, swagger_auto_schema
from rest_framework import serializers, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.authtoken.models import Token as UserToken
from rest_framework.authtoken.views import ObtainAuthToken as BaseObtainAuthToken
from rest_framework.exceptions import NotFound, ParseError, PermissionDenied
from rest_framework.generics import (
    CreateAPIView,
    GenericAPIView,
    ListAPIView,
    RetrieveAPIView,
)
from rest_framework.permissions import (
    DjangoModelPermissions,
    IsAdminUser,
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle  # get_ident method

from openwisp_radius.api.serializers import RadiusUserSerializer
from openwisp_users.api.authentication import BearerAuthentication, SesameAuthentication
from openwisp_users.api.permissions import IsOrganizationManager
from openwisp_users.api.views import ChangePasswordView as BasePasswordChangeView

from .. import settings as app_settings
from ..exceptions import PhoneTokenException, UserAlreadyVerified
from ..utils import generate_pdf, load_model
from . import freeradius_views
from .freeradius_views import AccountingFilter, AccountingViewPagination
from .permissions import IsRegistrationEnabled, IsSmsVerificationEnabled
from .serializers import (
    AuthTokenSerializer,
    ChangePhoneNumberSerializer,
    RadiusAccountingSerializer,
    RadiusBatchSerializer,
    ValidatePhoneTokenSerializer,
)
from .swagger import ObtainTokenRequest, ObtainTokenResponse, RegisterResponse
from .utils import ErrorDictMixin, IDVerificationHelper, is_registration_enabled

authorize = freeradius_views.authorize
postauth = freeradius_views.postauth
accounting = freeradius_views.accounting

_TOKEN_AUTH_FAILED = _('Token authentication failed')
renew_required = app_settings.DISPOSABLE_RADIUS_USER_TOKEN
logger = logging.getLogger(__name__)

User = get_user_model()
Organization = swapper.load_model('openwisp_users', 'Organization')
OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
PhoneToken = load_model('PhoneToken')
RadiusAccounting = load_model('RadiusAccounting')
RadiusToken = load_model('RadiusToken')
RadiusBatch = load_model('RadiusBatch')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
RegisteredUser = load_model('RegisteredUser')


class ThrottledAPIMixin(object):
    throttle_scope = 'others'


class BatchView(ThrottledAPIMixin, CreateAPIView):
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
                'The user {username} is not member of organization {organization}.'
            ).format(username=user.username, organization=self.organization.name)
            logger.info(message)
            raise serializers.ValidationError({'non_field_errors': [message]})


class DownloadRadiusBatchPdfView(ThrottledAPIMixin, DispatchOrgMixin, RetrieveAPIView):
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


class UserDetailsUpdaterMixin(object):
    def update_user_details(self, user):
        language = get_language_from_request(self.request)
        update_fields = ['last_login']
        if user.language != language:
            user.language = language
            update_fields.append('language')
        user.last_login = timezone.now()
        user.save(update_fields=update_fields)


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


@method_decorator(
    name='post',
    decorator=swagger_auto_schema(
        operation_description=(
            'Used by users to create new accounts, usually to access the internet.'
        ),
        responses={201: RegisterResponse},
    ),
)
class RegisterView(
    ThrottledAPIMixin, RadiusTokenMixin, DispatchOrgMixin, BaseRegisterView
):
    authentication_classes = tuple()
    permission_classes = (IsRegistrationEnabled,)

    def get_response_data(self, user):
        data = super().get_response_data(user)
        radius_token = self.get_or_create_radius_token(
            user, self.organization, enable_auth=False
        )
        data['radius_user_token'] = radius_token.key
        return data


register = RegisterView.as_view()


class ObtainAuthTokenView(
    DispatchOrgMixin,
    RadiusTokenMixin,
    BaseObtainAuthToken,
    IDVerificationHelper,
    UserDetailsUpdaterMixin,
):
    throttle_scope = 'obtain_auth_token'
    serializer_class = rest_auth_settings.TokenSerializer
    auth_serializer_class = AuthTokenSerializer
    authentication_classes = [SesameAuthentication]

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
        user = request.user
        if user.is_anonymous:
            serializer = self.auth_serializer_class(
                data=request.data, context={'request': request}
            )
            serializer.is_valid(raise_exception=True)
            user = self.get_user(serializer, *args, **kwargs)
        token, _ = UserToken.objects.get_or_create(user=user)
        self.get_or_create_radius_token(user, self.organization, renew=renew_required)
        self.update_user_details(user)
        context = {'view': self, 'request': request}
        serializer = self.serializer_class(instance=token, context=context)
        response = RadiusUserSerializer(user).data
        response.update(serializer.data)
        status_code = 200 if user.is_active else 401
        # If identity verification is required, check if user is verified
        if self._needs_identity_verification(
            {'slug': kwargs['slug']}
        ) and not self.is_identity_verified_strong(user):
            status_code = 401
        return Response(response, status=status_code)

    def get_user(self, serializer, *args, **kwargs):
        user = serializer.validated_data['user']
        self.validate_membership(user)
        return user

    def validate_membership(self, user):
        if not (user.is_superuser or user.is_member(self.organization)):
            if is_registration_enabled(self.organization):
                if self._needs_identity_verification(
                    org=self.organization
                ) and not self.is_identity_verified_strong(user):
                    raise PermissionDenied
                try:
                    org_user = OrganizationUser(
                        user=user, organization=self.organization
                    )
                    org_user.full_clean()
                    org_user.save()
                except ValidationError as error:
                    raise serializers.ValidationError(
                        {'non_field_errors': error.message_dict.pop('__all__')}
                    )
            else:
                message = _(
                    '{organization} does not allow self registration '
                    'of new accounts.'
                ).format(organization=self.organization.name)
                raise PermissionDenied(message)


obtain_auth_token = ObtainAuthTokenView.as_view()


class ValidateTokenSerializer(serializers.Serializer):
    token = serializers.CharField()


class ValidateAuthTokenView(
    DispatchOrgMixin,
    RadiusTokenMixin,
    CreateAPIView,
    IDVerificationHelper,
    UserDetailsUpdaterMixin,
):
    throttle_scope = 'validate_auth_token'
    serializer_class = ValidateTokenSerializer

    @swagger_auto_schema(request_body=ValidateTokenSerializer)
    def post(self, request, *args, **kwargs):
        """
        Used to check whether the auth token of a user is valid or not.
        """
        request_token = request.data.get('token')
        response = {'response_code': 'BLANK_OR_INVALID_TOKEN'}
        if request_token:
            try:
                token = UserToken.objects.select_related(
                    'user', 'user__registered_user'
                ).get(key=request_token)
            except UserToken.DoesNotExist:
                pass
            else:
                user = token.user
                self.get_or_create_radius_token(
                    user, self.organization, renew=renew_required
                )
                # user may be in the process of changing the phone number
                # in that case show the new phone number (which is not verified yet)
                if not self.is_identity_verified_strong(user):
                    phone_token = (
                        PhoneToken.objects.filter(user=user)
                        .order_by('-created')
                        .first()
                    )
                    user.phone_number = (
                        phone_token.phone_number if phone_token else user.phone_number
                    )
                response = RadiusUserSerializer(user).data
                context = {'view': self, 'request': request}
                token_data = rest_auth_settings.TokenSerializer(
                    token, context=context
                ).data
                token_data['auth_token'] = token_data.pop('key')
                token_data['response_code'] = 'AUTH_TOKEN_VALIDATION_SUCCESSFUL'
                response.update(token_data)
                self.update_user_details(token.user)
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
class UserAccountingView(ThrottledAPIMixin, DispatchOrgMixin, ListAPIView):
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


class PasswordChangeView(ThrottledAPIMixin, DispatchOrgMixin, BasePasswordChangeView):
    authentication_classes = (BearerAuthentication,)

    def get_permissions(self):
        return [IsAuthenticated()]

    def get_object(self):
        return self.request.user

    @swagger_auto_schema(responses={200: '`{"detail":"New password has been saved."}`'})
    def post(self, request, *args, **kwargs):
        """
        **Requires the user auth token (Bearer Token).**
        Allows users to change their password after using
        the `Reset password` endpoint.
        """
        self.validate_membership(request.user)
        return super().update(request, *args, **kwargs)


password_change = PasswordChangeView.as_view()


class PasswordResetView(ThrottledAPIMixin, DispatchOrgMixin, BasePasswordResetView):
    authentication_classes = tuple()

    @swagger_auto_schema(
        responses={
            200: '`{"detail": "Password reset e-mail has been sent."}`',
            400: '`{"detail": "The email field is required."}`',
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
        uid = user_pk_to_url_str(user)
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
        raise ParseError(_('The email field is required.'))


password_reset = PasswordResetView.as_view()


class PasswordResetConfirmView(
    ThrottledAPIMixin, DispatchOrgMixin, BasePasswordResetConfirmView
):
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
                uid = url_str_to_user_pk(self.request.POST['uid'])
                user = User.objects.get(pk=uid)
            except (User.DoesNotExist, ValidationError):
                raise Http404()
            self.validate_membership(user)
            return user


password_reset_confirm = PasswordResetConfirmView.as_view()


class CreatePhoneTokenView(
    ErrorDictMixin, BaseThrottle, DispatchOrgMixin, CreateAPIView
):
    throttle_scope = 'create_phone_token'
    authentication_classes = (BearerAuthentication,)
    permission_classes = (
        IsSmsVerificationEnabled,
        IsAuthenticated,
    )

    @swagger_auto_schema(
        operation_description=(
            """
            **Requires the user auth token (Bearer Token).**
            Used for SMS verification, sends a code via SMS to the
            phone number of the user.
            """
        ),
        request_body=no_body,
        responses={201: ''},
    )
    def post(self, request, *args, **kwargs):
        # Required for drf-yasg
        return super().post(request, *args, **kwargs)

    def create(self, *args, **kwargs):
        request = self.request
        self.validate_membership(request.user)
        phone_number = request.data.get('phone_number', request.user.phone_number)
        phone_token = PhoneToken(
            user=request.user,
            ip=self.get_ident(request),
            phone_number=phone_number,
        )
        try:
            phone_token.full_clean()
            if kwargs.get('enforce_unverified', True):
                phone_token._validate_already_verified()
        except ValidationError as e:
            error_dict = self._get_error_dict(e)
            raise serializers.ValidationError(error_dict)
        except UserAlreadyVerified as e:
            raise serializers.ValidationError({'user': str(e)})
        phone_token.save()
        return Response(None, status=201)


create_phone_token = CreatePhoneTokenView.as_view()


class ValidatePhoneTokenView(DispatchOrgMixin, GenericAPIView):
    throttle_scope = 'validate_phone_token'
    authentication_classes = (BearerAuthentication,)
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
            user.registered_user.is_verified = True
            user.registered_user.method = 'mobile_phone'
            user.is_active = True
            # Update username if phone_number is used as username
            if user.username == user.phone_number:
                user.username = phone_token.phone_number
            # now that the phone number is verified
            # we can write it to the user field
            user.phone_number = phone_token.phone_number
            user.save()
            user.registered_user.save()
            return Response(None, status=200)


validate_phone_token = ValidatePhoneTokenView.as_view()


class ChangePhoneNumberView(ThrottledAPIMixin, CreatePhoneTokenView):
    authentication_classes = (BearerAuthentication,)
    permission_classes = (
        IsSmsVerificationEnabled,
        IsAuthenticated,
    )
    serializer_class = ChangePhoneNumberSerializer

    @swagger_auto_schema(
        operation_description=(
            """
            **Requires the user auth token (Bearer Token).**
            Allows users to change their phone number, will flag the
            user as inactive and send them a verification code via SMS.
            """
        ),
        responses={200: ''},
    )
    def post(self, request, *args, **kwargs):
        # Required for drf-yasg
        return super().post(request, *args, **kwargs)

    def create(self, *args, **kwargs):
        serializer = self.get_serializer(
            data=self.request.data, context=self.get_serializer_context()
        )
        serializer.is_valid(raise_exception=True)
        # attempt to create the phone token before
        # the user is marked unverified, so that if the
        # creation of the phone token fails, the
        # the user's is_verified state remains unchanged
        self.create_phone_token(*args, **kwargs)
        serializer.save()
        return Response(None, status=200)

    def create_phone_token(self, *args, **kwargs):
        kwargs['enforce_unverified'] = False
        return super().create(*args, **kwargs)


change_phone_number = ChangePhoneNumberView.as_view()
