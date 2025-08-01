import logging

import phonenumbers
import swapper
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email
from dj_rest_auth.registration.serializers import (
    RegisterSerializer as BaseRegisterSerializer,
)
from dj_rest_auth.serializers import (
    PasswordResetSerializer as BasePasswordResetSerializer,
)
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.http import Http404
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from phonenumber_field.serializerfields import PhoneNumberField
from phonenumbers import PhoneNumberType, phonenumberutil
from rest_framework import serializers
from rest_framework.authtoken.serializers import (
    AuthTokenSerializer as BaseAuthTokenSerializer,
)
from rest_framework.fields import empty

from openwisp_radius.api.exceptions import CrossOrgRegistrationException
from openwisp_users.backends import UsersAuthenticationBackend

from .. import settings as app_settings
from ..base.forms import PasswordResetForm
from ..counters.exceptions import MaxQuotaReached, SkipCheck
from ..registration import REGISTRATION_METHOD_CHOICES
from ..utils import (
    get_group_checks,
    get_organization_radius_settings,
    get_user_group,
    load_model,
)
from .utils import ErrorDictMixin, IDVerificationHelper

logger = logging.getLogger(__name__)

RadiusPostAuth = load_model("RadiusPostAuth")
RadiusAccounting = load_model("RadiusAccounting")
RadiusBatch = load_model("RadiusBatch")
RadiusToken = load_model("RadiusToken")
RadiusGroupCheck = load_model("RadiusGroupCheck")
RadiusUserGroup = load_model("RadiusUserGroup")
RegisteredUser = load_model("RegisteredUser")
OrganizationUser = swapper.load_model("openwisp_users", "OrganizationUser")
Organization = swapper.load_model("openwisp_users", "Organization")
User = get_user_model()


class AllowAllUsersModelBackend(UsersAuthenticationBackend):
    def user_can_authenticate(self, user):
        return True


class AuthTokenSerializer(BaseAuthTokenSerializer):
    """
    Recognizes also inactive users.
    The API will still reject these users but the
    consumers need to know the credentials are valid
    to trigger account verification again.
    """

    def validate(self, attrs):
        username = attrs.get("username")
        password = attrs.get("password")

        if username and password:
            backend = AllowAllUsersModelBackend()
            user = backend.authenticate(
                request=self.context.get("request"),
                username=username,
                password=password,
            )
            if not user:
                msg = _(
                    "The credentials entered are not valid. "
                    "Please double-check and try again."
                )
                raise serializers.ValidationError(msg, code="authorization")
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg, code="authorization")

        attrs["user"] = user
        return attrs


class AllowedMobilePrefixMixin(object):
    def is_prefix_allowed(self, phone_number, mobile_prefixes):
        """
        Verifies if a phone number's international prefix is allowed
        """
        country_code = phonenumbers.parse(str(phone_number)).country_code
        if not mobile_prefixes:
            return True
        return "+" + str(country_code) in mobile_prefixes


class AuthorizeSerializer(serializers.Serializer):
    username = serializers.CharField(
        max_length=User._meta.get_field("username").max_length, write_only=True
    )
    password = serializers.CharField(style={"input_type": "password"}, write_only=True)


class RadiusPostAuthSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        help_text="The `password` is stored only on unsuccessful authorizations.",
        required=False,
        allow_blank=True,
        style={"input_type": "password"},
    )

    def validate(self, data):
        # do not save correct passwords in clear text
        if data["reply"] == "Access-Accept":
            data["password"] = ""
        passwd = data["password"]
        data["password"] = f"{passwd[:63]}\u2026" if len(passwd) > 64 else passwd
        return super().validate(data)

    class Meta:
        model = RadiusPostAuth
        fields = "__all__"
        read_only_fields = ("organization",)


STATUS_TYPE_CHOICES = (
    ("Start", "Start"),
    ("Interim-Update", "Interim-Update"),
    ("Stop", "Stop"),
    ("Accounting-On", "Accounting-On (ignored)"),
    ("Accounting-Off", "Accounting-Off (ignored)"),
)


class RadiusAccountingSerializer(serializers.ModelSerializer):
    framed_ip_address = serializers.IPAddressField(required=False, allow_blank=True)
    framed_ipv6_address = serializers.IPAddressField(
        required=False, allow_blank=True, protocol="IPv6"
    )
    session_time = serializers.IntegerField(required=False)
    stop_time = serializers.DateTimeField(required=False)
    update_time = serializers.DateTimeField(required=False)
    input_octets = serializers.IntegerField(required=False)
    output_octets = serializers.IntegerField(required=False)
    # this is needed otherwise serializer will ignore status_type
    # from the accounting request because it's not a model field
    status_type = serializers.ChoiceField(
        write_only=True, required=True, choices=STATUS_TYPE_CHOICES
    )

    def _disable_radius_token_auth(self, user):
        """
        Disables radius token auth capability unless
        OPENWISP_RADIUS_DISPOSABLE_RADIUS_USER_TOKEN is False
        """
        if not app_settings.DISPOSABLE_RADIUS_USER_TOKEN:
            return
        try:
            radius_token = RadiusToken.objects.get(user__username=user)
        except RadiusToken.DoesNotExist:
            pass
        else:
            radius_token.can_auth = False
            radius_token.save()

    def is_valid(self, raise_exception=False):
        try:
            return super().is_valid(raise_exception=raise_exception)
        except serializers.ValidationError as error:
            request = self.context.get("request", None)
            if request:
                logger.warn(
                    "Freeradius accounting request failed.\n"
                    f"Error: {error}\n"
                    f"Request payload: {request.data}"
                )
            raise error

    def run_validation(self, data):
        """
        Custom validation to handle empty strings in:
            - session_time
            - input_octets
            - output_octets
        """
        for field in ["session_time", "input_octets", "output_octets"]:
            # missing data in accounting start,
            # let's set zero as default value
            if data.get("status_type", None) == "Start" and data.get(field) == "":
                data[field] = 0
            # missing data in accounting data,
            # let's remove the empty string to
            # prevent the API from failing
            # the existing values stored in previous
            # interim-updates won't be changed
            if data.get("status_type", None) != "Start" and data.get(field) == "":
                del data[field]
        return super().run_validation(data)

    def validate(self, data):
        """
        We need to set some timestamps according to the accounting packet type
        * update_time: set everytime a Interim-Update / Stop packet is received
        * stop_time: set everytime a Stop packet is received
        * session_time: calculated if not present in the accounting packet
        :param data: accounting packet
        :return: Dict accounting packet
        """
        time = timezone.now()
        status_type = data.pop("status_type")
        if status_type == "Interim-Update":
            data["update_time"] = time
            data["stop_time"] = None
            data["terminate_cause"] = ""
        if status_type == "Stop":
            data["update_time"] = time
            data["stop_time"] = time
            self._disable_radius_token_auth(data["username"])
        return data

    def create(self, validated_data):
        username = validated_data.get("username", "")
        calling_station_id = validated_data.get("calling_station_id", "")
        if app_settings.API_ACCOUNTING_AUTO_GROUP and username != calling_station_id:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                logging.warning(f"No corresponding user found for username: {username}")
            else:
                organization_uuid = self.context.get("request").auth
                group = (
                    user.radiususergroup_set.filter(
                        group__organization__pk=organization_uuid
                    )
                    .order_by("priority")
                    .first()
                )
                groupname = group.groupname if group else None
                validated_data.update(groupname=groupname)
        return super().create(validated_data)

    def update(self, instance, acct_data, *args, **kwargs):
        acct_data = self._check_called_station_id(instance, acct_data)
        return super().update(instance, acct_data, *args, **kwargs)

    def _check_called_station_id(self, instance, acct_data):
        """
        if called_station_id has been converted by the
        convert_called_station_id command,
        do not overwrite it back to unconverted ID during interim updates
        """
        ids = app_settings.CALLED_STATION_IDS
        if not ids or instance.called_station_id == acct_data["called_station_id"]:
            return acct_data
        try:
            organization = acct_data["organization"]
            if (
                ids
                and organization
                and (organization.slug in ids or str(organization.id) in ids)
            ):
                # organization slug is maintained for backward compatibility
                # but will removed in future versions
                unconverted_ids = ids.get(str(organization.id), {}).get(
                    "unconverted_ids", []
                ) + ids.get(organization.slug, {}).get("unconverted_ids", [])
                if acct_data["called_station_id"] in unconverted_ids:
                    acct_data["called_station_id"] = instance.called_station_id
        except Exception:
            logger.exception("Got exception in _check_called_station_id")
        return acct_data

    class Meta:
        model = RadiusAccounting
        fields = "__all__"
        read_only_fields = ("organization",)


class UserGroupCheckSerializer(serializers.ModelSerializer):
    result = serializers.SerializerMethodField()
    type = serializers.SerializerMethodField()

    class Meta:
        model = RadiusGroupCheck
        fields = ("attribute", "op", "value", "result", "type")

    def get_result(self, obj):
        try:
            Counter = app_settings.CHECK_ATTRIBUTE_COUNTERS_MAP[obj.attribute]
            counter = Counter(
                user=self.context["user"],
                group=self.context["group"],
                group_check=obj,
            )
            # Python can handle 64 bit numbers and
            # hence we don't need to display Gigawords
            remaining = counter.check(gigawords=False)
            return int(obj.value) - remaining
        except MaxQuotaReached:
            return int(obj.value)
        except (SkipCheck, ValueError, KeyError):
            return None

    def get_type(self, obj):
        try:
            counter = app_settings.CHECK_ATTRIBUTE_COUNTERS_MAP[obj.attribute]
        except KeyError:
            return None
        else:
            return counter.get_attribute_type()


class UserRadiusUsageSerializer(serializers.Serializer):
    def to_representation(self, obj):
        organization = self.context["view"].organization
        user_group = get_user_group(obj, organization.pk)
        if not user_group:
            raise Http404
        group_checks = get_group_checks(user_group.group).values()
        checks_data = UserGroupCheckSerializer(
            group_checks, many=True, context={"user": obj, "group": user_group.group}
        ).data
        return {"checks": checks_data}


class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = "__all__"
        ref_name = "radius_user_group_serializer"


class UserSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True)

    class Meta:
        model = User
        fields = "__all__"


class RadiusOrganizationField(serializers.SlugRelatedField):
    def get_queryset(self):
        queryset = Organization.objects.all()
        request = self.context.get("request", None)
        if not request.user.is_superuser:
            queryset = queryset.filter(pk__in=request.user.organizations_dict.keys())
        return queryset


class RadiusBatchSerializer(serializers.ModelSerializer):
    organization = serializers.PrimaryKeyRelatedField(
        help_text=("UUID of the organization in which the radius batch is created."),
        read_only=True,
    )
    organization_slug = RadiusOrganizationField(
        help_text=("Slug of the organization for creating radius batch."),
        required=True,
        label="organization",
        slug_field="slug",
        write_only=True,
    )
    users = UserSerializer(
        many=True,
        read_only=True,
    )
    prefix = serializers.CharField(
        help_text=(
            "Prefix for creating usernames. "
            "Only required when `prefix` strategy is used.`"
        ),
        required=False,
    )
    csvfile = serializers.FileField(
        help_text=(
            "CSV file for extracting user's information. "
            "Only required when `csv` strategy is used.`"
        ),
        required=False,
    )
    pdf_link = serializers.SerializerMethodField(
        help_text=(
            "Downlaod link to PDF file containing user credentials. "
            "Provided only for `prefix` strategy.`"
        ),
        required=False,
        read_only=True,
    )
    number_of_users = serializers.IntegerField(
        help_text=(
            "Number of users to be generated. "
            "Only required when `prefix` strategy is used.`"
        ),
        required=False,
        write_only=True,
        min_value=1,
    )

    def get_pdf_link(self, obj):
        if isinstance(obj, RadiusBatch) and obj.strategy == "prefix":
            request = self.context.get("request")
            return request.build_absolute_uri(
                reverse(
                    "radius:download_rad_batch_pdf",
                    args=[obj.organization.slug, obj.pk],
                )
            )
        return None

    def validate(self, data):
        if data["strategy"] == "prefix" and not data.get("number_of_users"):
            raise serializers.ValidationError(
                {"number_of_users": _("The field number_of_users cannot be empty")}
            )
        validated_data = super().validate(data)
        # Additional Model Validation
        batch_data = validated_data.copy()
        batch_data.pop("number_of_users", None)
        batch_data["organization"] = batch_data.pop("organization_slug", None)
        instance = self.instance or self.Meta.model(**batch_data)
        instance.full_clean()
        return validated_data

    class Meta:
        model = RadiusBatch
        fields = "__all__"
        read_only_fields = ("created", "modified", "user_credentials")


class PasswordResetSerializer(BasePasswordResetSerializer):
    input = serializers.CharField()
    email = None
    password_reset_form_class = PasswordResetForm

    def validate_input(self, value):
        # Create PasswordResetForm with the serializer.
        # Check BasePasswordResetSerializer.validate_email for details.
        user = self.context.get("request").user
        self.reset_form = self.password_reset_form_class(data={"email": user.email})
        self.reset_form.is_valid()
        return value

    def save(self):
        request = self.context.get("request")
        password_reset_url = self.context.get("password_reset_url")
        # Set some values to trigger the send_email method.
        opts = {
            "use_https": request.is_secure(),
            "from_email": getattr(settings, "DEFAULT_FROM_EMAIL"),
            "email_template_name": ("custom_password_reset_email.html"),
            "request": request,
            "extra_email_context": {
                "subject": _("Password reset on %s") % (get_current_site(request).name),
                "call_to_action_url": password_reset_url,
                "call_to_action_text": _("Reset password"),
            },
        }
        opts.update(self.get_email_options())
        self.reset_form.save(**opts)


class RegisterSerializer(
    ErrorDictMixin,
    AllowedMobilePrefixMixin,
    BaseRegisterSerializer,
    IDVerificationHelper,
):
    phone_number = PhoneNumberField(
        help_text=_(
            "Required only when the organization has enabled SMS "
            'verification in its "Organization RADIUS Settings."'
        ),
        allow_blank=True,
        default="",
    )
    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)
    location = serializers.CharField(required=False)
    birth_date = serializers.DateField(required=False)
    method = serializers.ChoiceField(
        help_text=_(
            "Required only when the organization has mandatory identity "
            'verification in its "Organization RADIUS Settings."'
        ),
        default="",
        choices=REGISTRATION_METHOD_CHOICES,
    )

    def validate_phone_number(self, phone_number):
        org = self.context["view"].organization
        if get_organization_radius_settings(org, "sms_verification"):
            if not phone_number:
                raise serializers.ValidationError(_("This field is required."))
            mobile_prefixes = org.radius_settings.allowed_mobile_prefixes_list
            if not self.is_prefix_allowed(phone_number, mobile_prefixes):
                raise serializers.ValidationError(
                    _("This international mobile prefix is not allowed.")
                )
            phone_number_type = phonenumberutil.number_type(phone_number)
            allowed_types = [PhoneNumberType.MOBILE]
            if app_settings.ALLOW_FIXED_LINE_OR_MOBILE:
                allowed_types.append(PhoneNumberType.FIXED_LINE_OR_MOBILE)
            if phone_number_type not in allowed_types:
                raise serializers.ValidationError(
                    _("Only mobile phone numbers are allowed.")
                )
            if User.objects.filter(phone_number=phone_number).exists():
                raise serializers.ValidationError(
                    _("A user is already registered with this phone number.")
                )
        else:
            # Phone number should not be stored if sms verification is disabled
            phone_number = None
        return phone_number

    def validate_optional_fields(self, field_name, field_value, org):
        if field_name == "method":
            field_setting = (
                "mandatory"
                if self._needs_identity_verification({"slug": org.slug}) is True
                else None
            )
        else:
            field_setting = getattr(
                org.radius_settings, field_name
            ) or app_settings.OPTIONAL_REGISTRATION_FIELDS.get(field_name)
        if field_setting == "mandatory" and not field_value:
            raise serializers.ValidationError(
                {f"{field_name}": _("This field is required.")}
            )
        if field_setting == "disabled":
            field_value = ""
        return field_value

    def validate_cross_org_registration(self, error, data):
        error_dict = error.detail
        if (
            "username" not in error_dict
            and "email" not in error_dict
            and "phone_number" not in error_dict
        ):
            raise error

        def has_key(key):
            return key in error_dict and key in data

        user_lookup = Q()
        # Phone number is given preference over email and username.
        if has_key("phone_number"):
            user_lookup |= Q(phone_number=data["phone_number"])
        if has_key("username"):
            user_lookup |= Q(username=data["username"])
        if has_key("email"):
            user_lookup |= Q(email=data["email"])
        users = User.objects.filter(user_lookup).values_list("id", flat=True)
        if not users:
            # Error is not related to cross organization registration
            raise error
        # More that one user objects might be returned if a user
        # supplies information that belongs to two different accounts.
        # We ensure that none of the returned accounts belongs to the
        # current organization and selects the first one based on query
        # preference.
        if OrganizationUser.objects.filter(
            organization=self.context["view"].organization,
            user_id__in=users,
        ).exists():
            # User is registering to the organization it is already member of.
            raise error
        user_id = users[0]
        organizations = (
            OrganizationUser.objects.filter(user_id=user_id)
            .select_related("organization")
            .values("organization__name", "organization__slug")
        )
        organization_list = []
        for org in organizations:
            organization_list.append(
                {"slug": org["organization__slug"], "name": org["organization__name"]}
            )
        raise CrossOrgRegistrationException(
            {
                "details": _("A user like the one being registered already exists."),
                "organizations": organization_list,
            },
        )

    def run_validation(self, data=empty):
        try:
            return super().run_validation(data=data)
        except serializers.ValidationError as error:
            self.validate_cross_org_registration(error, data)

    def save(self, request):
        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        # commit=False does not save the user to the DB yet
        adapter.save_user(request, user, self, commit=False)
        # the custom_signup method contains the openwisp specific logic
        self.custom_signup(request, user)
        # create a RegisteredUser object for every user that registers through API
        RegisteredUser.objects.create(
            user=user,
            method=self.validated_data["method"],
        )
        setup_user_email(request, user, [])
        return user

    def custom_signup(self, request, user, save=True):
        phone_number = self.validated_data["phone_number"]
        if phone_number != self.fields["phone_number"].default:
            user.phone_number = phone_number
        org = self.context["view"].organization
        for field_name in [
            "first_name",
            "last_name",
            "location",
            "birth_date",
            "method",
        ]:
            value = self.validate_optional_fields(
                field_name, self.validated_data.get(field_name, ""), org
            )
            if value:
                setattr(user, field_name, value)
        try:
            user.full_clean()
        except ValidationError as e:
            raise serializers.ValidationError(self._get_error_dict(e))
        user.save()
        orgUser = OrganizationUser(organization=org, user=user)
        orgUser.full_clean()
        orgUser.save()


class ValidatePhoneTokenSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=8)


class ChangePhoneNumberSerializer(
    ErrorDictMixin, AllowedMobilePrefixMixin, serializers.Serializer
):
    phone_number = PhoneNumberField()

    @property
    def user(self):
        return self.context["request"].user

    def validate_phone_number(self, phone_number):
        if self.user.phone_number == phone_number:
            raise serializers.ValidationError(
                _("The new phone number must be different than the old one.")
            )
        org = self.context["view"].organization
        mobile_prefixes = org.radius_settings.allowed_mobile_prefixes_list
        if not self.is_prefix_allowed(phone_number, mobile_prefixes):
            raise serializers.ValidationError(
                _("This international mobile prefix is not allowed.")
            )
        return phone_number

    def save(self):
        # we do not update the phone number of the user
        # yet, tha will be done by the phone token validation view
        # once the phone number has been validated
        # at this point we flag the user as unverified again
        self.user.registered_user.is_verified = False
        self.user.registered_user.save()


class RadiusUserSerializer(serializers.ModelSerializer):
    """
    Used to return information about the logged in user
    """

    is_verified = serializers.BooleanField(source="registered_user.is_verified")
    method = serializers.CharField(
        source="registered_user.method",
        allow_null=True,
    )
    password_expired = serializers.BooleanField(source="has_password_expired")
    radius_user_token = serializers.CharField(source="radius_token.key", default=None)

    class Meta:
        model = User
        fields = [
            "username",
            "email",
            "phone_number",
            "first_name",
            "last_name",
            "birth_date",
            "location",
            "is_active",
            "is_verified",
            "method",
            "password_expired",
            "radius_user_token",
        ]
