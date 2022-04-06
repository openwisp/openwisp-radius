from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.urls import reverse

from ..utils import load_model
from . import FileMixin
from .mixins import BaseTestCase

RadiusBatch = load_model('RadiusBatch')


class TestCSVUpload(FileMixin, BaseTestCase):
    def test_generate_username_from_email(self):
        reader = [['', 'cleartext$password', 'rohith@openwisp.com', 'Rohith', 'ASRK']]
        batch = self._create_radius_batch(
            name='test', strategy='csv', csvfile=self._get_csvfile(reader)
        )
        batch.add(reader)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        self.assertEqual(batch.users.all().count(), 1)
        user = batch.users.first()
        self.assertEqual(user.username, 'rohith')
        self.assertEqual(user.email, 'rohith@openwisp.com')
        self.assertEqual(user.first_name, 'Rohith')
        self.assertEqual(user.last_name, 'ASRK')

    def test_generate_username_when_repeat(self):
        hashed_password = (
            'pbkdf2_sha256$100000$x3DUBnOFwraV$PU2dZ'
            'Zq1FcuBjagxVLPhhFvpicLn18fFCN5xiLsxATc='
        )
        cleartext_password = 'cleartext$password'
        reader = [
            ['rohith', cleartext_password, 'rohith@openwisp.com', 'Rohith', 'ASRK'],
            ['rohith', hashed_password, 'rohith@openwisp.org', '', ''],
        ]
        batch = self._create_radius_batch(
            name='test', strategy='csv', csvfile=self._get_csvfile(reader)
        )
        batch.add(reader)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        self.assertEqual(batch.users.all().count(), 2)
        users = [x.username for x in batch.users.all()]
        self.assertIn('rohith', users)
        self.assertIn('rohith1', users)

    def test_generate_password(self):
        reader = [['rohith', '', 'rohith@openwisp.com', '', '']]
        batch = self._create_radius_batch(
            name='test', strategy='csv', csvfile=self._get_csvfile(reader)
        )
        batch.add(reader)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        self.assertEqual(batch.users.all().count(), 1)
        user = batch.users.first()
        self.assertIsNotNone(user.password)

    def test_cleartext_password(self):
        cleartext_password = 'cleartext$password'
        reader = [
            ['rohith', cleartext_password, 'rohith@openwisp.com', 'Rohith', 'ASRK']
        ]
        batch = self._create_radius_batch(
            name='test', strategy='csv', csvfile=self._get_csvfile(reader)
        )
        batch.add(reader)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        self.assertEqual(batch.users.all().count(), 1)
        user = batch.users.first()
        self.assertNotEqual(cleartext_password, user.password)

    def test_hashed_password(self):
        hashed_password = (
            'pbkdf2_sha256$100000$x3DUBnOFwraV$PU2dZ'
            'Zq1FcuBjagxVLPhhFvpicLn18fFCN5xiLsxATc='
        )
        reader = [['rohith', hashed_password, 'rohith@openwisp.com', 'Rohith', 'ASRK']]
        batch = self._create_radius_batch(
            name='test', strategy='csv', csvfile=self._get_csvfile(reader)
        )
        batch.add(reader)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        self.assertEqual(batch.users.all().count(), 1)
        user = batch.users.first()
        self.assertEqual(hashed_password, user.password)


class TestPrefixUpload(FileMixin, BaseTestCase):
    def test_invalid_username(self):
        self.assertRaises(
            ValidationError,
            self._create_radius_batch,
            name='test',
            strategy='prefix',
            prefix="Test#1",
        )

    def test_valid_username(self):
        batch = self._create_radius_batch(
            name='test', strategy='prefix', prefix='Test1'
        )
        batch.prefix_add('test-prefix16', 5)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        self.assertEqual(batch.users.all().count(), 5)

    def test_valid_username_special_char(self):
        batch = self._create_radius_batch(
            name='test', strategy='prefix', prefix='Test_@+-.'
        )
        batch.prefix_add('test-prefix16', 5)
        self.assertEqual(RadiusBatch.objects.all().count(), 1)
        self.assertEqual(batch.users.all().count(), 5)

    @patch('openwisp_radius.settings.API_AUTHORIZE_REJECT', True)
    def test_verified_batch_user_creation(self):
        organization = self._get_org()
        radius_settings = organization.radius_settings
        auth_header = f'Bearer {organization.pk} {radius_settings.token}'
        radius_settings.needs_identity_verification = True
        radius_settings.full_clean()
        radius_settings.save()
        batch = self._create_radius_batch(
            name='test', strategy='prefix', prefix='Test', organization=organization
        )
        batch.prefix_add('test-prefix', 1)
        user = batch.users.first()
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': user.username, 'password': batch.user_credentials[0][1]},
            HTTP_AUTHORIZATION=auth_header,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                'control:Auth-Type': 'Accept',
                'Session-Timeout': 10800,
                'ChilliSpot-Max-Total-Octets': 3000000000,
            },
        )
        self.assertEqual(user.registered_user.is_verified, True)
        self.assertEqual(user.registered_user.method, 'manual')
