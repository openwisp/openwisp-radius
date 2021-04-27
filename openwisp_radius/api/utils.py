import logging

import swapper
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import APIException

logger = logging.getLogger(__name__)

Organization = swapper.load_model('openwisp_users', 'Organization')


class ErrorDictMixin(object):
    def _get_error_dict(self, error):
        dict_ = error.message_dict.copy()
        if '__all__' in dict_:
            dict_['non_field_errors'] = dict_.pop('__all__')
        return dict_


def is_sms_verification_enabled(org):
    try:
        return org.radius_settings.sms_verification
    except ObjectDoesNotExist:
        logger.exception(
            f'Got exception while accessing radius_settings for {org.name}'
        )
        raise APIException(
            _('Could not complete operation ' 'because of an internal misconfiguration')
        )


class ThrottledAPIMixin(object):
    throttle_scope = 'others'


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
