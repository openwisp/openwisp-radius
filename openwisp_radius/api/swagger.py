"""
The following serializers are not used to send
response to user but in swagger documentation of
the API.
"""

from rest_framework import serializers


class ObtainTokenBase(serializers.Serializer):
    class Meta:
        ref_name = 'OpenwispRadiusObtainToken'


class ObtainTokenRequest(ObtainTokenBase):
    username = serializers.CharField(
        max_length=150,
        write_only=True,
        help_text=('Username of the user for obtaining tokens.'),
    )
    password = serializers.CharField(
        max_length=128,
        write_only=True,
        help_text=('Password of the user for obtaining tokens.'),
    )


class ObtainTokenResponse(ObtainTokenBase):
    radius_user_token = serializers.CharField(
        max_length=40,
        read_only=True,
        help_text=('Radius token used for communication in FreeRADIUS API.'),
    )
    key = serializers.CharField(
        max_length=40,
        read_only=True,
        help_text=('User token used for communication with User api.'),
    )


class RegisterResponse(serializers.Serializer):
    radius_user_token = serializers.CharField(
        max_length=40,
        read_only=True,
        help_text=('Radius token used for communication in FreeRADIUS API.'),
    )
    key = serializers.CharField(
        max_length=40,
        read_only=True,
        help_text=(
            'Only send when `REST_USE_JWT` is `False`. '
            'User token used for communication with User api.'
        ),
    )
    token = serializers.CharField(
        read_only=True,
        help_text=('Only send when `REST_USE_JWT` is `True`.'),
    )
    user = serializers.CharField(
        read_only=True,
        help_text=('Only send when `REST_USE_JWT` is `True`.'),
    )
