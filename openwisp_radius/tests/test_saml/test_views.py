import os
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import swapper
from django.conf import settings
from django.contrib.auth import SESSION_KEY, get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse, reverse_lazy
from djangosaml2.tests import auth_response, conf
from djangosaml2.utils import get_session_id_from_saml2, saml2_from_httpredirect_request
from rest_framework.authtoken.models import Token

from openwisp_radius.saml.utils import get_url_or_path
from openwisp_users.tests.utils import TestOrganizationMixin
from openwisp_utils.tests import capture_any_output

from .utils import TestSamlMixin as BaseTestSamlMixin

OrganizationUser = swapper.load_model('openwisp_users', 'OrganizationUser')
Organization = swapper.load_model('openwisp_users', 'Organization')
RadiusToken = swapper.load_model('openwisp_radius', 'RadiusToken')
RegisteredUser = swapper.load_model('openwisp_radius', 'RegisteredUser')
OrganizationRadiusSettings = swapper.load_model(
    'openwisp_radius', 'OrganizationRadiusSettings'
)
User = get_user_model()


BASE_PATH = os.path.dirname(os.path.abspath(__file__))
METADATA_PATH = os.path.join(BASE_PATH, 'remote_idp_metadata.xml')
ATTRIBUTE_MAPS_DIR = os.path.join(BASE_PATH, 'attribute-maps')
CERT_PATH = os.path.join(BASE_PATH, 'mycert.pem')
KEY_PATH = os.path.join(BASE_PATH, 'mycert.key')


class TestSamlMixin(TestOrganizationMixin, BaseTestSamlMixin):
    def setUp(self):
        super().setUp()
        org = Organization.objects.get_or_create(slug='default')[0]
        org.radius_settings.saml_registration_enabled = True
        org.radius_settings.full_clean()
        org.radius_settings.save()


@override_settings(
    SAML_CONFIG=conf.create_conf(
        sp_host='sp.example.com',
        idp_hosts=['idp.example.com'],
        metadata_file=METADATA_PATH,
    ),
    SAML_ATTRIBUTE_MAPPING={'uid': ('email', 'username')},
    SAML_USE_NAME_ID_AS_USERNAME=False,
    SAML_DJANGO_USER_MAIN_ATTRIBUTE='email',
)
class TestAssertionConsumerServiceView(TestSamlMixin, TestCase):
    login_url = reverse('radius:saml2_login')

    def _get_relay_state(self, redirect_url, org_slug):
        return f'{redirect_url}?org={org_slug}'

    def _get_saml_response_for_acs_view(self, relay_state, uid='org_user@example.com'):
        response = self.client.get(self.login_url, {'RelayState': relay_state})
        saml2_req = saml2_from_httpredirect_request(response.url)
        session_id = get_session_id_from_saml2(saml2_req)
        self.add_outstanding_query(session_id, relay_state)
        return auth_response(session_id, uid), relay_state

    def _post_successful_auth_assertions(self, query_params, org_slug):
        self.assertEqual(User.objects.count(), 1)
        user_id = self.client.session[SESSION_KEY]
        user = User.objects.get(id=user_id)
        self.assertEqual(
            user.emailaddress_set.filter(verified=True, primary=True).count(), 1
        )
        self.assertEqual(user.username, 'org_user@example.com')
        self.assertEqual(OrganizationUser.objects.count(), 1)
        org_user = OrganizationUser.objects.get(user_id=user_id)
        self.assertEqual(org_user.organization.slug, org_slug)
        expected_query_params = {
            'next': [
                '/radius/saml2/additional-info/'
                '?username=org_user%40example.com'
                f'&token={Token.objects.get(user_id=user_id).key}'
                '&login_method=saml'
            ]
        }
        self.assertDictEqual(query_params, expected_query_params)

    @capture_any_output()
    def test_organization_slug_present(self):
        expected_redirect_url = '/radius/saml2/additional-info/'
        org_slug = 'default'
        relay_state = self._get_relay_state(
            redirect_url=expected_redirect_url, org_slug=org_slug
        )
        saml_response, relay_state = self._get_saml_response_for_acs_view(relay_state)
        response = self.client.post(
            reverse('radius:saml2_acs'),
            {
                'SAMLResponse': self.b64_for_post(saml_response),
                'RelayState': relay_state,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(get_url_or_path(response.url), expected_redirect_url)
        query_params = parse_qs(urlparse(response.url).query)
        self._post_successful_auth_assertions(query_params, org_slug)

    @capture_any_output()
    def test_invalid_email_raise_validation_error(self):
        invalid_email = 'invalid_email@example'
        relay_state = self._get_relay_state(
            redirect_url='https://captive-portal.example.com', org_slug='default'
        )
        saml_response, relay_state = self._get_saml_response_for_acs_view(
            relay_state, uid=invalid_email
        )
        with patch('logging.Logger.exception') as mocked_logger:
            self.client.post(
                reverse('radius:saml2_acs'),
                {
                    'SAMLResponse': self.b64_for_post(saml_response),
                    'RelayState': relay_state,
                },
            )
        mocked_logger.assert_called_once_with(
            'Failed email validation for "invalid_email@example" during'
            ' SAML user creation'
        )

    @capture_any_output()
    def test_relay_state_relative_path(self):
        expected_redirect_path = '/radius/saml2/additional-info/'
        org_slug = 'default'
        relay_state = self._get_relay_state(
            redirect_url=expected_redirect_path, org_slug=org_slug
        )
        saml_response, relay_state = self._get_saml_response_for_acs_view(relay_state)
        response = self.client.post(
            reverse('radius:saml2_acs'),
            {
                'SAMLResponse': self.b64_for_post(saml_response),
                'RelayState': relay_state,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(get_url_or_path(response.url), expected_redirect_path)
        query_params = parse_qs(urlparse(response.url).query)
        self._post_successful_auth_assertions(query_params, org_slug)

    @capture_any_output()
    def test_user_registered_with_non_saml_method(self):
        user = self._create_user(username='test-user', email='org_user@example.com')
        RegisteredUser.objects.create(user=user, method='manual')
        relay_state = self._get_relay_state(
            redirect_url='https://captive-portal.example.com', org_slug='default'
        )

        with self.subTest('Test username remains unchanged'):
            with patch(
                'openwisp_radius.settings.SAML_UPDATES_PRE_EXISTING_USERNAME', False
            ):
                saml_response, relay_state = self._get_saml_response_for_acs_view(
                    relay_state
                )
                response = self.client.post(
                    reverse('radius:saml2_acs'),
                    {
                        'SAMLResponse': self.b64_for_post(saml_response),
                        'RelayState': relay_state,
                    },
                )
                self.assertEqual(response.status_code, 302)
                user.refresh_from_db()
                self.assertEqual(user.username, 'test-user')

        with self.subTest('Test username gets updated'):
            with patch(
                'openwisp_radius.settings.SAML_UPDATES_PRE_EXISTING_USERNAME', True
            ):
                saml_response, relay_state = self._get_saml_response_for_acs_view(
                    relay_state
                )
                response = self.client.post(
                    reverse('radius:saml2_acs'),
                    {
                        'SAMLResponse': self.b64_for_post(saml_response),
                        'RelayState': relay_state,
                    },
                )
                self.assertEqual(response.status_code, 302)
                user.refresh_from_db()
                self.assertEqual(user.username, 'org_user@example.com')


@override_settings(SAML_ALLOWED_HOSTS=['captive-portal.example.com'])
class TestAdditionInfoView(TestSamlMixin, TestCase):
    view_path = reverse_lazy('radius:saml2_additional_info')

    def test_unauthenticated_user(self):
        response = self.client.get(self.view_path)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f'{settings.LOGIN_URL}?next={self.view_path}')

    def test_user_has_email(self):
        user = self._create_user()
        self.client.force_login(user)
        response = self.client.get(
            f'{self.view_path}?next=https://captive-portal.example.com/login/'
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, 'https://captive-portal.example.com/login/')

    def test_user_has_no_email(self):
        user = self._create_user()
        User.objects.filter(pk=user.pk).update(email='')
        self.client.force_login(user)
        url = f'{self.view_path}?next=https://captive-portal.example.com/login/'
        response = self.client.get(url)
        # Verify that a form is displayed to collect email
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            '<input type="email" name="email" maxlength="254" required id="id_email">',
        )

        # Make post request to set email
        response = self.client.post(url, data={'email': 'test@openwisp.org'})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, 'https://captive-portal.example.com/login/')
        user.refresh_from_db()
        self.assertEqual(user.email, 'test@openwisp.org')
        self.assertEqual(
            user.emailaddress_set.filter(email='test@openwisp.org').count(), 1
        )
        self.assertEqual(
            mail.outbox[0].subject, '[example.com] Please Confirm Your Email Address'
        )


@override_settings(
    SAML_CONFIG=conf.create_conf(
        sp_host='sp.example.com',
        idp_hosts=['idp.example.com'],
        metadata_file=METADATA_PATH,
    ),
    SAML_ATTRIBUTE_MAPPING={'uid': ('username',)},
    SAML_USE_NAME_ID_AS_USERNAME=False,
)
class TestLoginView(TestSamlMixin, TestCase):
    login_url = reverse('radius:saml2_login')

    def test_organization_absolute_path(self):
        redirect_url = 'https://captive-portal.example.com/login/'

        with self.subTest('Organization slug not present in URL'):
            with patch('logging.Logger.error') as mocked_logger:
                response = self.client.get(self.login_url, {'RelayState': redirect_url})
                mocked_logger.assert_called_once_with('Organization slug not provided')
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, 'Authentication Error')

        with self.subTest('Incorrect organization slug present in URL'):
            with patch('logging.Logger.error') as mocked_logger:
                response = self.client.get(
                    self.login_url,
                    {'RelayState': f'{redirect_url}?org=non-existent-org'},
                )
                mocked_logger.assert_called_once_with(
                    'Organization with the provided slug does not exist'
                )
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, 'Authentication Error')

    @capture_any_output()
    def test_authenticated_user(self):
        user = self._create_user()
        self.client.force_login(user)
        redirect_url = 'https://captive-portal.example.com'
        response = self.client.get(
            self.login_url,
            {'RelayState': f'{redirect_url}?org=default'},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn('idp.example.com', response.url)

    def test_saml_login_disabled(self):
        org = self._get_org('default')
        org.radius_settings.saml_registration_enabled = None
        org.radius_settings.save()
        redirect_url = 'https://captive-portal.example.com'
        with self.subTest('SAML authentication is disabled site-wide'):
            with patch(
                'openwisp_radius.settings.SAML_REGISTRATION_ENABLED', False
            ), patch.object(
                OrganizationRadiusSettings._meta.get_field('saml_registration_enabled'),
                'fallback',
                False,
            ):
                response = self.client.get(
                    self.login_url,
                    {'RelayState': f'{redirect_url}?org=default'},
                )
                self.assertEqual(response.status_code, 403)

        with self.subTest('SAML registration is disabled for organization'):
            org.radius_settings.saml_registration_enabled = False
            org.radius_settings.save()
            response = self.client.get(
                self.login_url,
                {'RelayState': f'{redirect_url}?org=default'},
            )
            self.assertEqual(response.status_code, 403)
            org.radius_settings.saml_registration_enabled = None
            org.radius_settings.save()
