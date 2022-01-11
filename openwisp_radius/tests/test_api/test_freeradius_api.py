import json
import logging
import uuid
from unittest import mock

import swapper
from celery.exceptions import OperationalError
from dateutil import parser
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.timezone import now
from freezegun import freeze_time

from openwisp_utils.tests import capture_any_output, catch_signal

from ... import registration
from ... import settings as app_settings
from ...api.freeradius_views import logger as freeradius_api_logger
from ...counters.exceptions import MaxQuotaReached, SkipCheck
from ...signals import radius_accounting_success
from ...utils import load_model
from ..mixins import ApiTokenMixin, BaseTestCase

User = get_user_model()
RadiusToken = load_model('RadiusToken')
RadiusAccounting = load_model('RadiusAccounting')
RadiusPostAuth = load_model('RadiusPostAuth')
RadiusGroupReply = load_model('RadiusGroupReply')
RegisteredUser = load_model('RegisteredUser')
OrganizationRadiusSettings = load_model('OrganizationRadiusSettings')
Organization = swapper.load_model('openwisp_users', 'Organization')

START_DATE = '2019-04-20T22:14:09+01:00'
_AUTH_TYPE_ACCEPT_RESPONSE = {
    'control:Auth-Type': 'Accept',
    'ChilliSpot-Max-Total-Octets': 3000000000,
    'Session-Timeout': 10800,
}
_AUTH_TYPE_REJECT_RESPONSE = {'control:Auth-Type': 'Reject'}
_BASE_COUNTER_CHECK = 'openwisp_radius.counters.base.BaseCounter.check'


class AcctMixin(object):
    _acct_url = reverse('radius:accounting')
    _acct_initial_data = {
        'unique_id': '75058e50',
        'session_id': '35000006',
        'nas_ip_address': '172.16.64.91',
        'session_time': 0,
        'input_octets': 0,
        'output_octets': 0,
    }
    _acct_post_data = {
        'username': 'admin',
        'realm': '',
        'nas_port_id': '1',
        'nas_port_type': 'Async',
        'session_time': '261',
        'authentication': 'RADIUS',
        'input_octets': '1111909',
        'output_octets': '1511074444',
        'called_station_id': '00-27-22-F3-FA-F1:hostname',
        'calling_station_id': '5c:7d:c1:72:a7:3b',
        'terminate_cause': 'User_Request',
        'service_type': 'Login-User',
        'framed_protocol': 'test',
        'framed_ip_address': '127.0.0.1',
        'framed_ipv6_address': '::1',
        'framed_ipv6_prefix': '0::/64',
        'framed_interface_id': '0000:0000:0000:0001',
        'delegated_ipv6_prefix': '0::/64',
    }

    @property
    def acct_post_data(self):
        """returns a copy of self._acct_data"""
        data = self._acct_initial_data.copy()
        data.update(self._acct_post_data.copy())
        return data


class TestFreeradiusApi(AcctMixin, ApiTokenMixin, BaseTestCase):
    _test_email = 'test@openwisp.org'

    def setUp(self):
        cache.clear()
        super().setUp()

    def test_invalid_token(self):
        self._get_org_user()
        auth_header = self.auth_header.replace(' ', '')  # removes spaces in token
        response = self._authorize_user(auth_header=auth_header)
        self.assertEqual(response.status_code, 400)

    def test_disabled_user_login(self):
        user = self._create_user(
            **{
                'username': 'barbar',
                'email': 'barbar@email.com',
                'password': 'molly',
                'is_active': False,
            }
        )
        self._create_org_user(**{'user': user})
        response = self._authorize_user(
            username='barbar', password='molly', auth_header=self.auth_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)

    @capture_any_output()
    def test_authorize_no_token_403(self):
        self._get_org_user()
        response = self._authorize_user()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['detail'],
            (
                'Radius token does not exist. Obtain a new radius token or provide '
                'the organization UUID and API token.'
            ),
        )

    @capture_any_output()
    def test_authorize_no_username_403(self):
        self._get_org_user()
        self._login_and_obtain_auth_token()
        response = self.client.get(reverse('radius:authorize'))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['detail'], 'username field is required.')

    def test_authorize_200(self):
        self._get_org_user()
        response = self._authorize_user(auth_header=self.auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)

    def _test_authorize_with_user_auth_helper(self, username, password):
        r = self._authorize_user(
            username=username, password=password, auth_header=self.auth_header
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, _AUTH_TYPE_ACCEPT_RESPONSE)

    def _test_authorize_without_auth_helper(self, username, password):
        r = self._authorize_user(username=username, password=password)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, _AUTH_TYPE_ACCEPT_RESPONSE)

    @capture_any_output()
    def test_authorize_with_user_auth(self):
        user = self._create_user(
            username='tester2',
            email='tester2@gmail.com',
            phone_number='+237675679232',
            password='tester',
        )

        self._create_org_user(organization=self._get_org(), user=user)

        with self.subTest('Test authorize with username'):
            self._test_authorize_with_user_auth_helper(user.username, 'tester')

        with self.subTest('Test authorize with email'):
            self._test_authorize_with_user_auth_helper(user.email, 'tester')

        with self.subTest('Test authorize with phone_number'):
            self._test_authorize_with_user_auth_helper(user.phone_number, 'tester')

        with self.subTest('Test authorization failure'):
            r = self._authorize_user('thisuserdoesnotexist', 'tester', self.auth_header)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.data, None)

    @capture_any_output()
    def test_authorize_without_user_auth(self):
        user = self._create_user(
            username='tester',
            email='tester@gmail.com',
            phone_number='+237675679231',
            password='tester',
        )
        self._create_org_user(organization=self._get_org(), user=user)
        with self.subTest('Test authorize with username'):
            self._test_authorize_with_user_auth_helper('tester', 'tester')

        with self.subTest('Test authorize with email'):
            self._test_authorize_with_user_auth_helper('tester@gmail.com', 'tester')

        with self.subTest('Test authorize with phone_number'):
            self._test_authorize_with_user_auth_helper('+237675679231', 'tester')

        with self.subTest('Test authorization failure'):
            r = self._authorize_user('thisuserdoesnotexist', 'tester')
            self.assertEqual(r.status_code, 403)
            self.assertEqual(
                r.data['detail'],
                (
                    'Radius token does not exist. Obtain a new radius token or provide '
                    'the organization UUID and API token.'
                ),
            )

    def test_authorize_user_with_email_as_username(self):
        user = self._create_user(
            username='tester',
            email='tester@gmail.com',
            phone_number='+237675679231',
            password='tester',
        )
        user1 = self._create_user(
            username='tester@gmail.com',
            email='tester1@gmail.com',
            phone_number='+237675679232',
            password='tester1',
        )
        self._create_org_user(organization=self._get_org(), user=user)
        self._create_org_user(organization=self._get_org(), user=user1)

        self._test_authorize_with_user_auth_helper(user.email, 'tester')

    def test_authorize_user_with_phone_number_as_username(self):
        user = self._create_user(
            username='tester',
            email='tester@gmail.com',
            phone_number='+237675679231',
            password='tester',
        )
        user1 = self._create_user(
            username='+237675679231',
            email='tester1@gmail.com',
            phone_number='+237675679232',
            password='tester1',
        )
        self._create_org_user(organization=self._get_org(), user=user)
        self._create_org_user(organization=self._get_org(), user=user1)

        self._test_authorize_with_user_auth_helper(user.phone_number, 'tester')

    def test_authorize_200_querystring(self):
        self._get_org_user()
        post_url = f'{reverse("radius:authorize")}{self.token_querystring}'
        response = self.client.post(
            post_url, {'username': 'tester', 'password': 'tester'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)

    def test_authorize_failed(self):
        response = self._authorize_user(
            username='baldo', password='ugo', auth_header=self.auth_header
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)

    def test_authorize_fail_auth_details_incomplete(self):
        for querystring in [
            f'?token={self.default_org.radius_settings.token}',
            f'?uuid={str(self.default_org.pk)}',
        ]:
            with self.subTest(querystring):
                post_url = f'{reverse("radius:authorize")}{querystring}'
                response = self.client.post(
                    post_url, {'username': 'tester', 'password': 'tester'}
                )
                self.assertEqual(response.status_code, 403)

    def test_authorize_wrong_password(self):
        self._get_org_user()
        response = self._authorize_user(password='wrong', auth_header=self.auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)

    def test_authorize_radius_token_200(self):
        self._get_org_user()
        rad_token = self._login_and_obtain_auth_token()
        response = self._authorize_user(password=rad_token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)

    def test_authorize_with_password_after_radius_token_expires(self):
        self.test_authorize_radius_token_200()
        self.assertFalse(RadiusToken.objects.get(user__username='tester').can_auth)
        response = self._authorize_user()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)

    def test_user_auth_token_disposed_after_auth(self):
        self._get_org_user()
        rad_token = self._login_and_obtain_auth_token()
        # Success but disable radius_token for authorization
        response = self._authorize_user(password=rad_token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)
        # Ensure cannot authorize with radius_token
        response = self._authorize_user(password=rad_token)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)
        # Ensure can authorize with password
        response = self._authorize_user()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)

    def test_user_auth_token_obtain_auth_token_renew(self):
        self._get_org_user()
        rad_token = self._login_and_obtain_auth_token()
        # Authorization works
        response = self._authorize_user(password=rad_token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)
        # Renew and authorize again
        second_rad_token = self._login_and_obtain_auth_token()
        response = self._authorize_user(password=second_rad_token)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(rad_token, second_rad_token)

    def test_authorize_multiple_org_interaction(self):
        self._get_org_user()
        self._login_and_obtain_auth_token()
        org2 = self._create_org(name='org2', slug='org2')
        rad_settings = OrganizationRadiusSettings.objects.create(organization=org2)
        # authorize authenticating as org2
        auth_header = f'Bearer {org2.pk} {rad_settings.token}'
        response = self._authorize_user(auth_header=auth_header)
        self.assertIsNone(response.data)
        self.assertEqual(response.status_code, 200)

    def test_authorize_unverified_user(self):
        self._get_org_user()
        org_settings = OrganizationRadiusSettings.objects.get(
            organization=self._get_org()
        )
        org_settings.needs_identity_verification = True
        org_settings.save()
        response = self._authorize_user(auth_header=self.auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)

    @mock.patch.object(registration, 'AUTHORIZE_UNVERIFIED', ['mobile_phone'])
    def test_authorize_unverified_user_with_special_method(self):
        org_user = self._get_org_user()
        reg_user = RegisteredUser(
            user=org_user.user, method='mobile_phone', is_verified=False
        )
        reg_user.full_clean()
        reg_user.save()
        org_settings = OrganizationRadiusSettings.objects.get(
            organization=self._get_org()
        )
        org_settings.needs_identity_verification = True
        org_settings.save()
        with self.assertNumQueries(9):
            response = self._authorize_user(auth_header=self.auth_header)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)

    def test_authorize_radius_token_unverified_user(self):
        user = self._get_org_user()
        org_settings = OrganizationRadiusSettings.objects.get(
            organization=user.organization
        )
        org_settings.needs_identity_verification = True
        org_settings.save()
        response = self.client.post(
            reverse('radius:user_auth_token', args=[user.organization.slug]),
            data={'username': 'tester', 'password': 'tester'},
        )
        self.assertEqual(response.status_code, 401)

    def test_authorize_200_with_replies(self):
        user = self._get_org_user().user
        rug = user.radiususergroup_set.first()
        reply1 = RadiusGroupReply(
            group=rug.group, attribute='Session-Timeout', op='=', value='3600'
        )
        reply1.full_clean()
        reply1.save()
        reply2 = RadiusGroupReply(
            group=rug.group, attribute='Idle-Timeout', op='=', value='500'
        )
        reply2.full_clean()
        reply2.save()
        post_url = f'{reverse("radius:authorize")}{self.token_querystring}'
        response = self.client.post(
            post_url, {'username': 'tester', 'password': 'tester'}
        )
        self.assertEqual(response.status_code, 200)
        expected = _AUTH_TYPE_ACCEPT_RESPONSE.copy()
        expected.update(
            {
                'Session-Timeout': {'op': '=', 'value': '3600'},
                'Idle-Timeout': {'op': '=', 'value': '500'},
            }
        )
        self.assertEqual(
            response.data,
            expected,
        )

    @capture_any_output()
    def test_authorize_counters_exception_handling(self):
        self._get_org_user()
        truncated_accept_response = {'control:Auth-Type': 'Accept'}

        with self.subTest('SkipCheck'):
            with mock.patch(_BASE_COUNTER_CHECK) as mocked_check:
                mocked_check.side_effect = SkipCheck(
                    message='Skip test',
                    level='error',
                    logger=logging,
                )
                response = self._authorize_user(auth_header=self.auth_header)
                self.assertEqual(mocked_check.call_count, len(app_settings.COUNTERS))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data, truncated_accept_response)

        with self.subTest('MaxQuotaReached'):
            with mock.patch(_BASE_COUNTER_CHECK) as mocked_check:
                mocked_check.side_effect = MaxQuotaReached(
                    message='MaxQuotaReached',
                    level='info',
                    logger=logging,
                    reply_message='reply MaxQuotaReached',
                )
                response = self._authorize_user(auth_header=self.auth_header)
                mocked_check.assert_called_once()
                self.assertEqual(response.status_code, 200)
                expected = _AUTH_TYPE_REJECT_RESPONSE.copy()
                expected['Reply-Message'] = 'reply MaxQuotaReached'
                self.assertEqual(response.data, expected)

        with self.subTest('Unexpected exception'):
            with mock.patch(_BASE_COUNTER_CHECK) as mocked_check:
                mocked_check.side_effect = ValueError('Unexpected error')
                response = self._authorize_user(auth_header=self.auth_header)
                self.assertEqual(mocked_check.call_count, len(app_settings.COUNTERS))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.data, truncated_accept_response)

    def test_authorize_counters_reply_interaction(self):
        user = self._get_org_user().user
        rug = user.radiususergroup_set.first()
        reply = RadiusGroupReply(
            group=rug.group, attribute='Session-Timeout', op='=', value='3600'
        )
        reply.full_clean()
        reply.save()

        with self.subTest('remaining lower than reply'):
            with mock.patch(_BASE_COUNTER_CHECK) as mocked_check:
                mocked_check.return_value = 1200
                response = self._authorize_user(auth_header=self.auth_header)
                self.assertEqual(mocked_check.call_count, len(app_settings.COUNTERS))
                self.assertEqual(response.status_code, 200)
                expected = _AUTH_TYPE_ACCEPT_RESPONSE.copy()
                expected['Session-Timeout'] = 1200
                expected['ChilliSpot-Max-Total-Octets'] = 1200
                self.assertEqual(response.data, expected)

        with self.subTest('remaining higher than reply'):
            with mock.patch(_BASE_COUNTER_CHECK) as mocked_check:
                mocked_check.return_value = 3000000000
                response = self._authorize_user(auth_header=self.auth_header)
                self.assertEqual(mocked_check.call_count, len(app_settings.COUNTERS))
                self.assertEqual(response.status_code, 200)
                expected = _AUTH_TYPE_ACCEPT_RESPONSE.copy()
                expected['Session-Timeout'] = {'op': '=', 'value': '3600'}
                self.assertEqual(response.data, expected)

        with self.subTest('Counters disabled'):
            with mock.patch.object(app_settings, 'COUNTERS', []):
                with self.assertNumQueries(6):
                    response = self._authorize_user(auth_header=self.auth_header)
                self.assertEqual(response.status_code, 200)
                expected = {
                    'control:Auth-Type': 'Accept',
                    'Session-Timeout': {'op': '=', 'value': '3600'},
                }
                self.assertEqual(response.data, expected)

        with self.subTest('incorrect reply value'):
            reply.value = 'broken'
            reply.save()
            mocked_check.return_value = 1200
            with mock.patch.object(freeradius_api_logger, 'warning') as mocked_warning:
                response = self._authorize_user(auth_header=self.auth_header)
                mocked_warning.assert_called_once_with(
                    'Session-Timeout value ("broken") cannot be converted to integer.'
                )
            self.assertEqual(mocked_check.call_count, len(app_settings.COUNTERS))
            self.assertEqual(response.status_code, 200)
            expected = _AUTH_TYPE_ACCEPT_RESPONSE.copy()
            expected['Session-Timeout'] = 10800
            expected['ChilliSpot-Max-Total-Octets'] = 3000000000
            self.assertEqual(response.data, expected)

    def test_postauth_accept_201(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = self._get_postauth_params()
        response = self.client.post(
            reverse('radius:postauth'), params, HTTP_AUTHORIZATION=self.auth_header
        )
        params['password'] = ''
        self.assertEqual(RadiusPostAuth.objects.filter(**params).count(), 1)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)

    def test_postauth_radius_token_expired_201(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        self.assertEqual(RadiusToken.objects.all().count(), 0)
        self._get_org_user()
        self._create_radius_token(can_auth=False)
        params = self._get_postauth_params(**{'username': 'tester', 'password': ''})
        response = self.client.post(reverse('radius:postauth'), params)
        self.assertEqual(RadiusToken.objects.all().count(), 1)
        self.assertEqual(RadiusPostAuth.objects.filter(**params).count(), 1)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)

    def test_postauth_radius_token_accept_201(self):
        self._get_org_user()
        self._login_and_obtain_auth_token()
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = self._get_postauth_params(
            **{'username': 'tester', 'password': 'tester'}
        )
        response = self.client.post(reverse('radius:postauth'), params)
        params['password'] = ''
        self.assertEqual(RadiusPostAuth.objects.filter(**params).count(), 1)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)

    def test_postauth_accept_201_querystring(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = self._get_postauth_params()
        post_url = f'{reverse("radius:postauth")}{self.token_querystring}'
        response = self.client.post(post_url, params)
        params['password'] = ''
        self.assertEqual(RadiusPostAuth.objects.filter(**params).count(), 1)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)

    def test_postauth_reject_201(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = {'username': 'molly', 'password': 'barba', 'reply': 'Access-Reject'}
        params = self._get_postauth_params(**params)
        response = self.client.post(
            reverse('radius:postauth'), params, HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)
        self.assertEqual(
            RadiusPostAuth.objects.filter(username='molly', password='barba').count(),
            1,
        )

    def test_postauth_reject_201_empty_fields(self):
        params = {
            'reply': 'Access-Reject',
            'called_station_id': '',
            'calling_station_id': '',
        }
        params = self._get_postauth_params(**params)
        response = self.client.post(
            reverse('radius:postauth'), params, HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(RadiusPostAuth.objects.filter(**params).count(), 1)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)

    def test_postauth_400(self):
        response = self.client.post(
            reverse('radius:postauth'), {}, HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        self.assertEqual(response.status_code, 400)

    @capture_any_output()
    def test_postauth_no_token_403(self):
        response = self.client.post(reverse('radius:postauth'), {'username': 'tester'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['detail'],
            (
                'Radius token does not exist. Obtain a new radius token or provide '
                'the organization UUID and API token.'
            ),
        )

    def test_postauth_long_password_access_reject(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = self._get_postauth_params(
            **{'password': get_random_string(length=128), 'reply': 'Access-Reject'}
        )
        response = self.client.post(
            reverse('radius:postauth'), params, HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusPostAuth.objects.count(), 1)
        pa = RadiusPostAuth.objects.first()
        with self.subTest('Ensure validation does not fail'):
            pa.full_clean()
        with self.subTest('Ensure max length is honored'):
            self.assertEqual(
                len(pa.password), RadiusPostAuth._meta.get_field('password').max_length
            )

    def test_postauth_long_password_access_accept(self):
        self.assertEqual(RadiusPostAuth.objects.all().count(), 0)
        params = self._get_postauth_params(
            **{'password': get_random_string(length=128), 'reply': 'Access-Accept'}
        )
        response = self.client.post(
            reverse('radius:postauth'), params, HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusPostAuth.objects.count(), 1)
        pa = RadiusPostAuth.objects.first()
        with self.subTest('Ensure validation does not fail'):
            pa.full_clean()
        with self.subTest('Ensure password is not saved'):
            self.assertEqual(len(pa.password), 0)

    def post_json(self, data):
        """
        performs a post using application/json as content type
        emulating the exact behaviour of freeradius 3
        """
        return self.client.post(
            self._acct_url,
            data=json.dumps(data),
            HTTP_AUTHORIZATION=self.auth_header,
            content_type='application/json',
        )

    def _prep_start_acct_data(self):
        data = self.acct_post_data
        data['status_type'] = 'Start'
        return self._get_accounting_params(**data)

    def assertAcctData(self, ra, data):
        """
        compares the values in data (dict)
        with the values of a RadiusAccounting instance
        to ensure they match
        """
        # we don't expect the organization field
        # because it will be inferred from the auth token
        self.assertNotIn('organization', data)
        # but we still want to ensure the
        # organization is filled correctly
        data['organization'] = self.default_org
        for key, _ in data.items():
            if key in ('status_type', 'framed_ipv6_address'):
                continue
            ra_value = getattr(ra, key)
            data_value = data[key]
            _type = type(ra_value)
            if _type != type(data_value):
                data_value = _type(data_value)
            self.assertEqual(ra_value, data_value, msg=key)

    @capture_any_output()
    def test_accounting_no_token_403(self):
        response = self.client.post(self._acct_url, {'username': 'tester'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.data['detail'],
            (
                'Radius token does not exist. Obtain a new radius token or provide '
                'the organization UUID and API token.'
            ),
        )

    @freeze_time(START_DATE)
    @mock.patch('openwisp_radius.receivers.send_login_email.delay')
    def test_accounting_start_200(self, send_login_email):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        ra = self._create_radius_accounting(**self._acct_initial_data)
        data = self._prep_start_acct_data()
        with catch_signal(radius_accounting_success) as handler:
            response = self.post_json(data)
        handler.assert_called_once()
        view = handler.mock_calls[0].kwargs.get('view')
        self.assertTrue(hasattr(view, 'request'))
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra.refresh_from_db()
        self.assertAcctData(ra, data)

    @mock.patch(
        'openwisp_radius.receivers.send_login_email.delay', side_effect=OperationalError
    )
    @mock.patch('openwisp_radius.receivers.logger')
    def test_celery_broker_unreachable(self, logger, *args):
        data = self._prep_start_acct_data()
        self.post_json(data)
        logger.warning.assert_called_with('Celery broker is unreachable')

    @mock.patch('openwisp_radius.receivers.send_login_email.delay')
    def test_accounting_start_radius_token_201(self, send_login_email):
        self._get_org_user()
        self._login_and_obtain_auth_token()
        data = self._prep_start_acct_data()
        data.update(username='tester')
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        with catch_signal(radius_accounting_success) as handler:
            response = self.client.post(
                self._acct_url,
                data=json.dumps(data),
                content_type='application/json',
            )
        handler.assert_called_once()
        send_login_email.assert_called_once()
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 1)

    def test_accounting_start_radius_token_expired_200(self):
        self._get_org_user()
        self._create_radius_token(can_auth=False)
        self._create_radius_accounting(**self._acct_initial_data)
        data = self._prep_start_acct_data()
        data.update(username='tester')
        response = self.client.post(
            self._acct_url,
            data=json.dumps(data),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b'')

    @freeze_time(START_DATE)
    def test_accounting_start_200_querystring(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        ra = self._create_radius_accounting(**self._acct_initial_data)
        data = self._prep_start_acct_data()
        post_url = f'{self._acct_url}{self.token_querystring}'
        response = self.client.post(
            post_url, json.dumps(data), content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra.refresh_from_db()
        self.assertAcctData(ra, data)

    @freeze_time(START_DATE)
    @capture_any_output()
    def test_accounting_start_coova_chilli(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = {
            'status_type': 'Start',
            'session_id': '5a4f59aa00000001',
            'unique_id': 'd11a8069e261040d8b01b9135bdb8dc9',
            'username': 'username',
            'realm': '',
            'nas_ip_address': '192.168.182.1',
            'nas_port_id': '1',
            'nas_port_type': 'Wireless-802.11',
            'session_time': '',
            'authentication': '',
            'input_octets': '',
            'output_octets': '',
            'called_station_id': 'C0-4A-00-EE-D1-0D',
            'calling_station_id': 'A4-02-B9-D3-FD-29',
            'terminate_cause': '',
            'service_type': '',
            'framed_protocol': '',
            'framed_ip_address': '192.168.182.3',
            'framed_ipv6_address': '::ffff:c0a8:b603',
            'framed_ipv6_prefix': '0::/64',
            'framed_interface_id': '0000:ffff:c0a8:b603',
            'delegated_ipv6_prefix': '0::/64',
        }
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra = RadiusAccounting.objects.last()
        ra.refresh_from_db()
        data['session_time'] = 0
        data['input_octets'] = 0
        data['output_octets'] = 0
        self.assertEqual(ra.session_time, 0)
        self.assertEqual(ra.input_octets, 0)
        self.assertEqual(ra.output_octets, 0)
        self.assertAcctData(ra, data)

    @freeze_time(START_DATE)
    @capture_any_output()
    def test_accounting_start_201(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = self.acct_post_data
        data['status_type'] = 'Start'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        self.assertAcctData(RadiusAccounting.objects.first(), data)

    @freeze_time(START_DATE)
    def test_accounting_update_200(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        ra = self._create_radius_accounting(**self._acct_initial_data)
        data = self.acct_post_data
        data['status_type'] = 'Interim-Update'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra.refresh_from_db()
        self.assertEqual(ra.update_time.timetuple(), now().timetuple())
        data['terminate_cause'] = ''
        self.assertAcctData(ra, data)

    @mock.patch.object(
        app_settings,
        'CALLED_STATION_IDS',
        {
            'test-org': {
                'openvpn_config': [
                    {'host': '127.0.0.1', 'port': 7505, 'password': 'somepassword'}
                ],
                'unconverted_ids': ['00-27-22-F3-FA-F1:hostname'],
            }
        },
    )
    @freeze_time(START_DATE)
    def test_accounting_update_conversion_200(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        ra = self._create_radius_accounting(**self._acct_initial_data)

        with self.subTest('should not overwrite back to unconverted ID'):
            ra.called_station_id = '00-00-11-11-22-22'
            ra.save()
            data = self.acct_post_data
            data['status_type'] = 'Interim-Update'
            data = self._get_accounting_params(**data)
            response = self.post_json(data)
            self.assertEqual(response.status_code, 200)
            self.assertIsNone(response.data)
            self.assertEqual(RadiusAccounting.objects.count(), 1)
            ra.refresh_from_db()
            self.assertEqual(ra.called_station_id, '00-00-11-11-22-22')

        with self.subTest('should overwrite if different called station ID'):
            ra.called_station_id = '00-00-11-11-22-22'
            ra.save()
            data = self.acct_post_data
            data['status_type'] = 'Interim-Update'
            data = self._get_accounting_params(**data)
            # this called station ID is not in the unconverted_ids list
            # and simulates the situation in which the user roams
            # to a different device and hence the called station ID can change
            data['called_station_id'] = '00-00-22-22-33-33'
            response = self.post_json(data)
            self.assertEqual(response.status_code, 200)
            self.assertIsNone(response.data)
            self.assertEqual(RadiusAccounting.objects.count(), 1)
            ra.refresh_from_db()
            self.assertEqual(ra.called_station_id, '00-00-22-22-33-33')

    @freeze_time(START_DATE)
    @capture_any_output()
    def test_accounting_update(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        with self.subTest('test interim update on unexisting radius accounting'):
            data = self.acct_post_data
            data['status_type'] = 'Interim-Update'
            data = self._get_accounting_params(**data)
            response = self.post_json(data)
            self.assertEqual(response.status_code, 201)
            self.assertIsNone(response.data)
            self.assertEqual(RadiusAccounting.objects.count(), 1)
            ra = RadiusAccounting.objects.first()
            self.assertEqual(ra.update_time.timetuple(), now().timetuple())
            data['terminate_cause'] = ''
            self.assertAcctData(ra, data)
        with self.subTest('test interim update on stopped radius accounting'):
            data = {
                **self.acct_post_data,
                'start_time': '2018-03-02T00:43:24.020460+01:00',
                'stop_time': '2018-03-02T00:43:24.020460+01:00',
                'terminate_cause': 'User Request',
                'unique_id': 'd11a8069e261040d8b01b9135bdb8dc9',
            }
            ra = self._create_radius_accounting(**data)
            self.assertEqual(ra.stop_time, parser.parse(data['stop_time']))
            self.assertEqual(ra.terminate_cause, data['terminate_cause'])
            data['status_type'] = 'Interim-Update'
            response = self.post_json(data)
            self.assertEqual(response.status_code, 200)
            self.assertIsNone(response.data)
            ra.refresh_from_db()
            self.assertEqual(ra.stop_time, None)
            self.assertEqual(ra.terminate_cause, '')

    @freeze_time(START_DATE)
    def test_accounting_stop_200(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        ra = self._create_radius_accounting(**self._acct_initial_data)
        # reload date object in order to store ra.start_time
        ra.refresh_from_db()
        start_time = ra.start_time
        data = self.acct_post_data
        data['status_type'] = 'Stop'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra.refresh_from_db()
        self.assertEqual(ra.update_time.timetuple(), now().timetuple())
        self.assertEqual(ra.stop_time.timetuple(), now().timetuple())
        self.assertEqual(ra.start_time, start_time)
        self.assertAcctData(ra, data)

    @freeze_time(START_DATE)
    @capture_any_output()
    def test_accounting_stop_201(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = self.acct_post_data
        data['status_type'] = 'Stop'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 1)
        ra = RadiusAccounting.objects.first()
        self.assertEqual(ra.update_time.timetuple(), now().timetuple())
        self.assertEqual(ra.stop_time.timetuple(), now().timetuple())
        self.assertEqual(ra.start_time.timetuple(), now().timetuple())
        self.assertAcctData(ra, data)

    def test_user_auth_token_disabled_on_stop(self):
        self._get_org_user()
        radtoken = self._create_radius_token(can_auth=True)
        # Send Accounting stop request
        data = self.acct_post_data
        data.update(username='tester', status_type='Stop')
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        radtoken.refresh_from_db()
        self.assertFalse(radtoken.can_auth)

    @freeze_time(START_DATE)
    def test_user_auth_token_org_accounting_stop(self):
        self._get_org_user()
        self.org2 = self._create_org(**{'name': 'test', 'slug': 'test'})
        self._create_org_user(**{'organization': self.org2})
        # Start Accounting with first organzation
        response = self.client.post(
            reverse('radius:user_auth_token', args=[self.default_org.slug]),
            {'username': 'tester', 'password': 'tester'},
        )
        data = self._prep_start_acct_data()
        data.update(username='tester')
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        # Get radius token with second organization
        response = self.client.post(
            reverse('radius:user_auth_token', args=[self.org2.slug]),
            {'username': 'tester', 'password': 'tester'},
        )
        # Test RadiusAccounting is terminated with correct cause
        self.assertEqual(
            RadiusAccounting.objects.filter(
                username='tester',
                organization=self.default_org,
                terminate_cause='NAS_Request',
                stop_time__isnull=False,
            ).count(),
            1,
        )

    @freeze_time(START_DATE)
    @capture_any_output()
    def test_radius_accounting_nas_stop_regression(self):
        # create a first RadiusAccounting object to ensure
        # we'll have 2 records when the next test method is executed
        unique_id = uuid.uuid4().hex
        data = self._prep_start_acct_data()
        data.update(
            username='tester',
            stop_time=START_DATE,
            terminate_cause='User-Request',
            unique_id=unique_id,
            session_id=unique_id,
        )
        response = self.post_json(data)
        self.assertEqual(response.status_code, 201)
        self.test_user_auth_token_org_accounting_stop()

    @freeze_time(START_DATE)
    def test_accounting_400_missing_status_type(self):
        data = self._get_accounting_params(**self.acct_post_data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 400)
        self.assertIn('status_type', response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 0)

    @freeze_time(START_DATE)
    def test_accounting_400_invalid_status_type(self):
        data = self.acct_post_data
        data['status_type'] = 'INVALID'
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 400)
        self.assertIn('status_type', response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 0)

    @freeze_time(START_DATE)
    def test_accounting_400_validation_error(self):
        data = self.acct_post_data
        data['status_type'] = 'Start'
        del data['nas_ip_address']
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 400)
        self.assertIn('nas_ip_address', response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 0)

    def test_accounting_list_200(self):
        data1 = self.acct_post_data
        data1.update(
            dict(
                session_id='35000006',
                unique_id='75058e50',
                input_octets=9900909,
                output_octets=1513075509,
            )
        )
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(
            dict(
                session_id='40111116',
                unique_id='12234f69',
                input_octets=3000909,
                output_octets=1613176609,
            )
        )
        self._create_radius_accounting(**data2)
        data3 = self.acct_post_data
        data3.update(
            dict(
                session_id='89897654',
                unique_id='99144d60',
                input_octets=4440909,
                output_octets=1119074409,
            )
        )
        self._create_radius_accounting(**data3)
        response = self.client.get(
            f'{self._acct_url}?page_size=1&page=1',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['output_octets'], data3['output_octets'])
        self.assertEqual(item['input_octets'], data3['input_octets'])
        self.assertEqual(item['nas_ip_address'], '172.16.64.91')
        self.assertEqual(item['calling_station_id'], '5c:7d:c1:72:a7:3b')
        response = self.client.get(
            f'{self._acct_url}?page_size=1&page=2',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['output_octets'], data2['output_octets'])
        self.assertEqual(item['nas_ip_address'], '172.16.64.91')
        self.assertEqual(item['input_octets'], data2['input_octets'])
        self.assertEqual(item['called_station_id'], '00-27-22-F3-FA-F1:hostname')
        response = self.client.get(
            f'{self._acct_url}?page_size=1&page=3',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['username'], 'admin')
        self.assertEqual(item['calling_station_id'], '5c:7d:c1:72:a7:3b')
        self.assertEqual(item['output_octets'], data1['output_octets'])
        self.assertEqual(item['input_octets'], data1['input_octets'])

    def test_accounting_filter_username(self):
        data1 = self.acct_post_data
        data1.update(dict(username='test_user', unique_id='75058e50'))
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(dict(username='admin', unique_id='99144d60'))
        self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?username=test_user',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['username'], 'test_user')

    def test_accounting_filter_called_station_id(self):
        data1 = self.acct_post_data
        data1.update(dict(called_station_id='E0-CA-40-EE-D1-0D', unique_id='99144d60'))
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(dict(called_station_id='C0-CA-40-FE-E1-9D', unique_id='85144d60'))
        self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?called_station_id=E0-CA-40-EE-D1-0D',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['called_station_id'], 'E0-CA-40-EE-D1-0D')

    def test_accounting_filter_calling_station_id(self):
        data1 = self.acct_post_data
        data1.update(dict(calling_station_id='4c:8d:c2:80:a7:4c', unique_id='99144d60'))
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(dict(calling_station_id='5c:6d:c2:80:a7:4c', unique_id='85144d60'))
        self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?calling_station_id=4c:8d:c2:80:a7:4c',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['calling_station_id'], '4c:8d:c2:80:a7:4c')

    @freeze_time(START_DATE)
    def test_accounting_filter_start_time(self):
        data1 = self.acct_post_data
        data1.update(dict(unique_id='99144d60'))
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(
            dict(start_time='2018-03-02T00:43:24.020460+01:00', unique_id='85144d60')
        )
        ra = self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?start_time=2018-03-01',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 2)
        self.assertEqual(response.status_code, 200)
        item = response.data[-1]
        self.assertEqual(parser.parse(item['start_time']), ra.start_time)

    @freeze_time(START_DATE)
    def test_accounting_filter_stop_time(self):
        data1 = self.acct_post_data
        data1.update(
            dict(
                start_time=START_DATE,
                stop_time=START_DATE.replace('04-20', '04-21'),
                unique_id='99144d60',
            )
        )
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        stop_time = '2018-03-02T11:43:24.020460+01:00'
        data2.update(
            dict(
                start_time='2018-03-02T10:43:24.020460+01:00',
                stop_time=stop_time,
                unique_id='85144d60',
            )
        )
        ra = self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?stop_time=2018-03-02 21:43:25',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(parser.parse(item['stop_time']), ra.stop_time)

    def test_accounting_filter_is_open(self):
        data1 = self.acct_post_data
        data1.update(dict(stop_time=None, unique_id='99144d60'))
        self._create_radius_accounting(**data1)
        data2 = self.acct_post_data
        data2.update(
            dict(stop_time='2018-03-02T00:43:24.020460+01:00', unique_id='85144d60')
        )
        ra = self._create_radius_accounting(**data2)
        response = self.client.get(
            f'{self._acct_url}?is_open=true',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(item['stop_time'], None)
        response = self.client.get(
            f'{self._acct_url}?is_open=false',
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.status_code, 200)
        item = response.data[0]
        self.assertEqual(parser.parse(item['stop_time']), ra.stop_time)

    @freeze_time(START_DATE)
    def test_coova_accounting_on_200(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = {
            'status_type': 'Accounting-On',
            'session_id': '',
            'unique_id': '569533dad629d47d8b122826d3ed7f3d',
            'username': '',
            'realm': '',
            'nas_ip_address': '192.168.182.1',
            'nas_port_id': '',
            'nas_port_type': 'Wireless-802.11',
            'session_time': '',
            'authentication': '',
            'input_octets': '',
            'output_octets': '',
            'called_station_id': 'C0-4A-00-EE-D1-0D',
            'calling_station_id': '00-00-00-00-00-00',
            'terminate_cause': '',
            'service_type': '',
            'framed_protocol': '',
            'framed_ip_address': '',
            'framed_ipv6_address': '',
            'framed_ipv6_prefix': '',
            'framed_interface_id': '',
            'delegated_ipv6_prefix': '',
        }
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 0)

    @freeze_time(START_DATE)
    def test_coova_accounting_off_200(self):
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        data = {
            'status_type': 'Accounting-Off',
            'session_id': '',
            'unique_id': '569533dad629d47d8b122826d3ed7f3d',
            'username': '',
            'realm': '',
            'nas_ip_address': '192.168.182.1',
            'nas_port_id': '',
            'nas_port_type': 'Wireless-802.11',
            'session_time': '',
            'authentication': '',
            'input_octets': '',
            'output_octets': '',
            'called_station_id': 'C0-4A-00-EE-D1-0D',
            'calling_station_id': '00-00-00-00-00-00',
            'terminate_cause': '0',
            'service_type': '',
            'framed_protocol': '',
            'framed_ip_address': '',
            'framed_ipv6_address': '',
            'framed_ipv6_prefix': '',
            'framed_interface_id': '',
            'delegated_ipv6_prefix': '',
        }
        response = self.post_json(data)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)
        self.assertEqual(RadiusAccounting.objects.count(), 0)

    def test_accounting_when_nas_using_pfsense_started(self):
        data = {
            "status_type": "Accounting-On",
            "session_id": "",
            "unique_id": "bc184fc97e3d58a9583d2ca5bc2ee210",
            "username": "",
            "realm": "",
            "nas_ip_address": "10.0.0.14",
            "nas_port_id": "",
            "nas_port_type": "",
            "session_time": "",
            "authentication": "RADIUS",
            "input_octets": "",
            "output_octets": "",
            "called_station_id": "00:00:45:a7:73:e3:owisp_gw1",
            "calling_station_id": "",
            "terminate_cause": "",
            "service_type": "Login-User",
            "framed_protocol": "",
            "framed_ip_address": "",
        }
        response = self.client.post(
            self._acct_url,
            data=json.dumps(data),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)

    def test_get_authorize_view(self):
        url = f'{reverse("radius:authorize")}{self.token_querystring}'
        r = self.client.get(url, HTTP_ACCEPT='text/html')
        self.assertEqual(r.status_code, 405)
        expected = f'<form action="{reverse("radius:authorize")}'
        self.assertIn(expected, r.content.decode())

    def test_accounting_start_403(self):
        data = self.acct_post_data
        data['status_type'] = 'Start'
        data['organization'] = str(self.default_org.pk)
        data = self._get_accounting_params(**data)
        response = self.post_json(data)
        self.assertEqual(response.status_code, 403)
        self.assertIn('setting the organization', str(response.data['detail']))

    def test_accounting_show_only_token_org(self):
        org = Organization.objects.create(name='org1')
        self.assertEqual(RadiusAccounting.objects.count(), 0)
        nas_ip = '127.0.0.1'
        test1 = RadiusAccounting(
            session_id='asd1', organization=org, nas_ip_address=nas_ip, unique_id='123'
        )
        test1.full_clean()
        test1.save()
        test2 = RadiusAccounting(
            session_id='asd2',
            organization=self.default_org,
            nas_ip_address=nas_ip,
            unique_id='1234',
        )
        test2.full_clean()
        test2.save()
        data = self.client.get(self._acct_url, HTTP_AUTHORIZATION=self.auth_header)
        self.assertEqual(len(data.json()), 1)
        self.assertEqual(data.json()[0]['organization'], str(self.default_org.pk))

    def test_user_accounting_list_empty_diff_organization(self):
        self.test_accounting_start_200()
        self._get_org_user()
        with self.subTest("Auth Token"):
            self._login_and_obtain_auth_token(username='tester')
            response = self.client.get(f'{self._acct_url}?username=tester')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.json()), 0)
        with self.subTest("HTTP Auth"):
            response = self.client.get(
                f'{self._acct_url}?username=tester', HTTP_AUTHORIZATION=self.auth_header
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.json()), 0)


class TestApiReject(ApiTokenMixin, BaseTestCase):
    @classmethod
    def setUpClass(cls):
        app_settings.API_AUTHORIZE_REJECT = True

    @classmethod
    def tearDownClass(cls):
        app_settings.API_AUTHORIZE_REJECT = False

    def test_disabled_user_login(self):
        User.objects.create_user(username='barbar', password='molly', is_active=False)
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': 'barbar', 'password': 'molly'},
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, _AUTH_TYPE_REJECT_RESPONSE)

    def test_authorize_401(self):
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': 'baldo', 'password': 'ugo'},
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data, _AUTH_TYPE_REJECT_RESPONSE)


class TestAutoGroupname(ApiTokenMixin, BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        app_settings.API_ACCOUNTING_AUTO_GROUP = True

    def test_automatic_groupname_account_enabled(self):
        user = User.objects.create_superuser(
            username='username1', email='admin@admin.com', password='qwertyuiop'
        )
        usergroup1 = self._create_radius_usergroup(
            groupname='group1',
            priority=2,
            username='testgroup1',
            group=self._create_radius_group(name='group1'),
        )
        usergroup2 = self._create_radius_usergroup(
            groupname='group2',
            priority=1,
            username='testgroup2',
            group=self._create_radius_group(name='group2'),
        )
        user.radiususergroup_set.set([usergroup1, usergroup2])
        self.client.post(
            f'{reverse("radius:accounting")}{self.token_querystring}',
            {
                'status_type': 'Start',
                'session_time': '',
                'input_octets': '',
                'output_octets': '',
                'nas_ip_address': '127.0.0.1',
                'session_id': '48484',
                'unique_id': '1515151',
                'username': 'username1',
            },
        )
        accounting_created = RadiusAccounting.objects.get(username='username1')
        self.assertEqual(accounting_created.groupname, 'test-org-group2')
        user.delete()

    def test_multiple_radius_group_with_different_org_and_priority(self):
        user = User.objects.create_superuser(
            username='username1', email='admin@admin.com', password='qwertyuiop'
        )
        organizations = Organization.objects.all()
        usergroup1 = self._create_radius_usergroup(
            groupname='group1',
            priority=1,
            username='testgroup1',
            group=self._create_radius_group(
                name='group1', organization=organizations.first()
            ),
        )
        usergroup2 = self._create_radius_usergroup(
            groupname='group2',
            priority=2,
            username='testgroup2',
            group=self._create_radius_group(
                name='group2', organization=organizations.last()
            ),
        )
        user.radiususergroup_set.set([usergroup1, usergroup2])
        self.client.post(
            f'{reverse("radius:accounting")}{self.token_querystring}',
            {
                'status_type': 'Start',
                'session_time': '',
                'input_octets': '',
                'output_octets': '',
                'nas_ip_address': '127.0.0.1',
                'session_id': '48484',
                'unique_id': '1515151',
                'username': 'username1',
            },
        )
        accounting_created = RadiusAccounting.objects.get(username='username1')
        self.assertEqual(accounting_created.groupname, 'test-org-group2')
        user.delete()

    @mock.patch('openwisp_radius.api.serializers.logging')
    def test_mac_authentication_with_no_logging(self, logger):
        username = '5c:7d:c1:72:a7:3b'
        self.client.post(
            f'{reverse("radius:accounting")}{self.token_querystring}',
            {
                'status_type': 'Start',
                'session_time': '',
                'input_octets': '',
                'output_octets': '',
                'nas_ip_address': '127.0.0.1',
                'session_id': '48484',
                'unique_id': '1515151',
                'username': username,
                'calling_station_id': username,
            },
        )
        logger.warning.assert_not_called()
        accounting_created = RadiusAccounting.objects.get(username=username)
        self.assertEqual(accounting_created.groupname, None)


class TestAutoGroupnameDisabled(ApiTokenMixin, BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        app_settings.API_ACCOUNTING_AUTO_GROUP = False

    def test_account_creation_api_automatic_groupname_disabled(self):
        user = User.objects.create_superuser(
            username='username1', email='admin@admin.com', password='qwertyuiop'
        )
        usergroup1 = self._create_radius_usergroup(
            groupname='group1', priority=2, username='testgroup1'
        )
        usergroup2 = self._create_radius_usergroup(
            groupname='group2', priority=1, username='testgroup2'
        )
        user.radiususergroup_set.set([usergroup1, usergroup2])
        url = f'{reverse("radius:accounting")}{self.token_querystring}'
        self.client.post(
            url,
            {
                'status_type': 'Start',
                'session_time': '',
                'input_octets': '',
                'output_octets': '',
                'nas_ip_address': '127.0.0.1',
                'session_id': '48484',
                'unique_id': '1515151',
                'username': 'username1',
            },
        )
        accounting_created = RadiusAccounting.objects.get(username='username1')
        self.assertIsNone(accounting_created.groupname)
        user.delete()


class TestClientIpApi(ApiTokenMixin, BaseTestCase):
    def setUp(self):
        self._get_org_user()
        self.params = {'username': 'tester', 'password': 'tester'}
        self.fail_msg = (
            'Request rejected: Client IP address (127.0.0.1) is not in '
            'the list of IP addresses allowed to consume the freeradius API.'
        )
        self.freeradius_hosts_path = 'openwisp_radius.settings.FREERADIUS_ALLOWED_HOSTS'
        self.client.post(
            reverse('radius:user_auth_token', args=[self._get_org().slug]), self.params
        )

    def test_cache(self):
        def authorize_and_assert(numOfQueries, ip_list):
            with self.assertNumQueries(numOfQueries):
                response = self.client.post(reverse('radius:authorize'), self.params)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)
            self.assertEqual(cache.get(f'ip-{org.pk}'), ip_list)

        cache.clear()
        org = self._get_org()
        self.assertEqual(cache.get(f'ip-{org.pk}'), None)
        with self.subTest('Without Cache'):
            authorize_and_assert(11, [])
        with self.subTest('With Cache'):
            authorize_and_assert(8, [])
        with self.subTest('Organization Settings Updated'):
            radsetting = OrganizationRadiusSettings.objects.get(organization=org)
            radsetting.freeradius_allowed_hosts = '127.0.0.1,192.0.2.0'
            radsetting.save()
            authorize_and_assert(8, ['127.0.0.1', '192.0.2.0'])
        with self.subTest('Cache Deleted'):
            cache.clear()
            authorize_and_assert(11, ['127.0.0.1', '192.0.2.0'])

    def test_ip_from_setting_valid(self):
        response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)

    @capture_any_output()
    def test_ip_from_setting_invalid(self):
        test_fail_msg = (
            'Request rejected: (localhost) in organization settings or '
            'settings.py is not a valid IP address. Please contact administrator.'
        )
        with mock.patch(self.freeradius_hosts_path, ['localhost']):
            response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['detail'], test_fail_msg)

    def test_ip_from_radsetting_valid(self):
        with mock.patch(self.freeradius_hosts_path, []):
            radsetting = OrganizationRadiusSettings.objects.get(
                organization=self._get_org()
            )
        radsetting.freeradius_allowed_hosts = '127.0.0.1'
        radsetting.save()
        response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)

    @capture_any_output()
    def test_ip_from_radsetting_invalid(self):
        test_fail_msg = (
            'Request rejected: (127.0.0.500) in organization settings or '
            'settings.py is not a valid IP address. Please contact administrator.'
        )
        radsetting = OrganizationRadiusSettings.objects.get(
            organization=self._get_org()
        )
        radsetting.freeradius_allowed_hosts = '127.0.0.500'
        radsetting.save()
        with mock.patch(self.freeradius_hosts_path, []):
            response = self.client.post(reverse('radius:authorize'), self.params)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['detail'], test_fail_msg)

    @capture_any_output()
    def test_ip_from_radsetting_not_exist(self):
        org2 = self._create_org(**{'name': 'test', 'slug': 'test'})
        self._create_org_user(**{'organization': org2})
        self.client.post(reverse('radius:user_auth_token', args=[org2.slug]))
        with self.subTest('FREERADIUS_ALLOWED_HOSTS is 127.0.0.1'):
            response = self.client.post(reverse('radius:authorize'), self.params)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, _AUTH_TYPE_ACCEPT_RESPONSE)
        with self.subTest('Empty Settings'), mock.patch(self.freeradius_hosts_path, []):
            response = self.client.post(reverse('radius:authorize'), self.params)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.data['detail'], self.fail_msg)


class TestOgranizationRadiusSettings(ApiTokenMixin, BaseTestCase):
    def setUp(self):
        cache.clear()
        self.org = self._create_org(**{'name': 'test', 'slug': 'test'})

    def test_string_representation(self):
        rad = OrganizationRadiusSettings.objects.create(organization=self.org)
        self.assertEqual(str(rad), rad.organization.name)

    def test_default_token(self):
        rad = OrganizationRadiusSettings.objects.create(organization=self.org)
        self.assertEqual(32, len(rad.token))

    def test_bad_token(self):
        try:
            rad = OrganizationRadiusSettings(
                token='bad.t.o.k.e.n', organization=self.org
            )
            rad.full_clean()
        except ValidationError as e:
            self.assertEqual(
                e.message_dict['token'][0],
                'This value must not contain spaces, dots or slashes.',
            )

    def test_cache(self):
        rad = OrganizationRadiusSettings.objects.create(
            token='12345', organization=self.org
        )
        self._get_org_user()
        token_querystring = f'?token={rad.token}&uuid={str(self.org.pk)}'
        post_url = f'{reverse("radius:authorize")}{token_querystring}'
        # Clear cache before sending request
        cache.clear()
        self.client.post(post_url, {'username': 'tester', 'password': 'tester'})
        with self.subTest('Cache & token match'):
            self.assertEqual(rad.token, cache.get(rad.organization.pk))
        with self.subTest('Force changed corrupt cache returns 403'):
            cache.set(rad.organization.pk, 'wrong-value')
            response = self.client.post(
                post_url, {'username': 'tester', 'password': 'tester'}
            )
            self.assertEqual(response.status_code, 403)
        with self.subTest('Updated cache with radius setting token'):
            rad.token = '1234567'
            rad.save()
            self.assertEqual(rad.token, cache.get(rad.organization.pk))
        with self.subTest('Cache Miss: radius settings deleted'):
            rad.delete()
            self.assertEqual(None, cache.get(rad.organization.pk))

    def test_no_org_radius_setting(self):
        self._get_org_user()
        token_querystring = f'?token=12345&uuid={str(self.org.pk)}'
        post_url = f'{reverse("radius:authorize")}{token_querystring}'
        r = self.client.post(post_url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.data, {'detail': 'Token authentication failed'})

    def test_uuid_in_cache(self):
        rad = OrganizationRadiusSettings.objects.create(
            token='12345', organization=self.org
        )
        cache.set('uuid', str(self.org.pk), 30)
        self._get_org_user()
        token_querystring = f'?token={rad.token}&uuid={str(self.org.pk)}'
        post_url = f'{reverse("radius:authorize")}{token_querystring}'
        r = self.client.post(post_url, {'username': 'tester', 'password': 'tester'})
        self.assertEqual(r.status_code, 200)

    def test_default_organisation_radius_settings(self):
        org = self._get_org()
        self.assertTrue(hasattr(org, 'radius_settings'))
        self.assertIsInstance(org.radius_settings, OrganizationRadiusSettings)

    def test_sms_phone_required(self):
        radius_settings = OrganizationRadiusSettings(
            organization=self.org, sms_verification=True, sms_sender=''
        )
        try:
            radius_settings.full_clean()
        except ValidationError as e:
            self.assertIn('sms_sender', e.message_dict)
        else:
            self.fail('ValidationError not raised')
