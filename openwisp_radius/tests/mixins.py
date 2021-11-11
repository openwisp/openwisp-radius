import os

import swapper
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from openwisp_utils.tests import AssertNumQueriesSubTestMixin

from ..utils import load_model
from . import CallCommandMixin as BaseCallCommandMixin
from . import CreateRadiusObjectsMixin
from . import PostParamsMixin as BasePostParamsMixin

User = get_user_model()
RadiusBatch = load_model('RadiusBatch')
RadiusToken = load_model('RadiusToken')
Organization = swapper.load_model('openwisp_users', 'Organization')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')


class GetEditFormInlineMixin(object):
    def _get_org_edit_form_inline_params(self, user, org):
        params = super()._get_org_edit_form_inline_params(user, org)
        if OrganizationRadiusSettings.objects.filter(organization=org).exists():
            params.update(
                {
                    'radius_settings-TOTAL_FORMS': 1,
                    'radius_settings-INITIAL_FORMS': 0,
                    'radius_settings-MIN_NUM_FORMS': 0,
                    'radius_settings-MAX_NUM_FORMS': 1,
                    'radius_settings-0-token': 'random-token-value',
                    'radius_settings-0-sms_sender': '',
                    'radius_settings-0-sms_meta_data': '',
                    'radius_settings-0-id': '',
                    'radius_settings-0-organization': str(org.pk),
                }
            )
        else:
            params.update(
                {
                    'radius_settings-TOTAL_FORMS': 0,
                    'radius_settings-INITIAL_FORMS': 0,
                    'radius_settings-MIN_NUM_FORMS': 0,
                    'radius_settings-MAX_NUM_FORMS': 0,
                }
            )
        return params

    def _get_user_edit_form_inline_params(self, user, organization):
        params = super()._get_user_edit_form_inline_params(user, organization)
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
                # registered user inline
                'registered_user-TOTAL_FORMS': 0,
                'registered_user-INITIAL_FORMS': 0,
                'registered_user-MIN_NUM_FORMS': 0,
                'registered_user-MAX_NUM_FORMS': 0,
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
    _test_email = 'test@openwisp.org'

    def setUp(self):
        super().setUp()
        org = self.default_org
        rad = self.default_org.radius_settings
        self.auth_header = f'Bearer {org.pk} {rad.token}'
        self.token_querystring = f'?token={rad.token}&uuid={str(org.pk)}'

    def _register_user(self, extra_params=None, expect_201=True, expect_users=1):
        self._superuser_login()
        if expect_users is not None:
            self.assertEqual(User.objects.count(), expect_users)
        url = reverse('radius:rest_register', args=[self.default_org.slug])
        params = {
            'username': self._test_email,
            'email': self._test_email,
            'password1': 'password',
            'password2': 'password',
        }
        if extra_params:
            params.update(extra_params)
        response = self.client.post(
            url,
            params,
        )
        if expect_201:
            self.assertEqual(response.status_code, 201)
        return response

    def _radius_batch_csv_data(self, **kwargs):
        options = self._get_post_defaults(
            {
                'organization_slug': self._get_org().slug,
                'name': 'test-csv',
                'strategy': 'csv',
            }
        )
        options.update(**kwargs)
        return options

    def _radius_batch_prefix_data(self, **kwargs):
        options = self._get_post_defaults(
            {
                'organization_slug': self._get_org().slug,
                'name': 'test-prefix',
                'prefix': 'test-prefix',
                'number_of_users': 3,
                'strategy': 'prefix',
            }
        )
        options.update(**kwargs)
        return options

    def _authorize_user(self, username='tester', password='tester', auth_header=None):
        if auth_header:
            return self.client.post(
                reverse('radius:authorize'),
                {'username': username, 'password': password},
                HTTP_AUTHORIZATION=auth_header,
            )
        return self.client.post(
            reverse('radius:authorize'),
            {'username': username, 'password': password},
        )

    def _login_and_obtain_auth_token(self, username='tester', password='tester'):
        login_payload = {'username': username, 'password': password}
        login_url = reverse('radius:user_auth_token', args=[self.default_org.slug])
        login_response = self.client.post(login_url, data=login_payload)
        return login_response.json()['radius_user_token']


class BaseTestCase(AssertNumQueriesSubTestMixin, DefaultOrgMixin, TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        os.makedirs(settings.MEDIA_ROOT, exist_ok=True)

    def tearDown(self):
        for radbatch in RadiusBatch.objects.all():
            radbatch.delete()

    def _superuser_login(self):
        admin = self._get_admin()
        self.client.force_login(admin)
