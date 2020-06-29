import os

import swapper
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase

from ..utils import load_model
from . import CallCommandMixin as BaseCallCommandMixin
from . import CreateRadiusObjectsMixin
from . import PostParamsMixin as BasePostParamsMixin

User = get_user_model()
RadiusBatch = load_model('RadiusBatch')
Organization = swapper.load_model('openwisp_users', 'Organization')


class GetEditFormInlineMixin(object):
    def _get_edit_form_inline_params(self, user, organization):
        params = super()._get_edit_form_inline_params(user, organization)
        rug = user.radiususergroup_set.first()
        if rug is not None:
            params.update(
                {
                    # radius user group inline
                    'radiususergroup_set-TOTAL_FORMS': 1,
                    'radiususergroup_set-INITIAL_FORMS': 1,
                    'radiususergroup_set-MIN_NUM_FORMS': 0,
                    'radiususergroup_set-MAX_NUM_FORMS': 1000,
                    'radiususergroup_set-0-priority': 1,
                    'radiususergroup_set-0-group': str(rug.group.pk),
                    'radiususergroup_set-0-id': str(rug.pk),
                    'radiususergroup_set-0-user': str(rug.user.pk),
                }
            )
        else:
            params.update(
                {
                    # radius user group inline
                    'radiususergroup_set-TOTAL_FORMS': 0,
                    'radiususergroup_set-INITIAL_FORMS': 0,
                    'radiususergroup_set-MIN_NUM_FORMS': 0,
                    'radiususergroup_set-MAX_NUM_FORMS': 0,
                }
            )
        params.update(
            {
                # social account inline
                'socialaccount_set-TOTAL_FORMS': 0,
                'socialaccount_set-INITIAL_FORMS': 0,
                'socialaccount_set-MIN_NUM_FORMS': 0,
                'socialaccount_set-MAX_NUM_FORMS': 0,
                # phone token inline
                'phonetoken_set-TOTAL_FORMS': 0,
                'phonetoken_set-INITIAL_FORMS': 0,
                'phonetoken_set-MIN_NUM_FORMS': 0,
                'phonetoken_set-MAX_NUM_FORMS': 0,
            }
        )
        return params


class CallCommandMixin(BaseCallCommandMixin):
    def _call_command(self, command, **kwargs):
        Organization.objects.get_or_create(name='test-organization')
        options = dict(organization='test-organization')
        kwargs.update(options)
        super()._call_command(command, **kwargs)


class PostParamsMixin(BasePostParamsMixin):
    def _get_post_defaults(self, options, model=None):
        if not model or hasattr(model, 'organization'):
            options.update({'organization': str(self._get_org().pk)})
        return super()._get_post_defaults(options, model)


class DefaultOrgMixin(CreateRadiusObjectsMixin):
    def setUp(self):
        self.default_org = self._get_org()
        super().setUp()


class ApiTokenMixin(BasePostParamsMixin):
    def setUp(self):
        super().setUp()
        org = self.default_org
        rad = self.default_org.radius_settings
        self.auth_header = 'Bearer {0} {1}'.format(org.pk, rad.token)
        self.token_querystring = '?token={0}&uuid={1}'.format(rad.token, str(org.pk))


class BaseTestCase(DefaultOrgMixin, TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        os.makedirs(settings.MEDIA_ROOT, exist_ok=True)

    def tearDown(self):
        for radbatch in RadiusBatch.objects.all():
            radbatch.delete()

    def _superuser_login(self):
        user = User.objects.create_superuser(
            username='admin', password='admin', email='test@test.org'
        )
        self.client.force_login(user)
