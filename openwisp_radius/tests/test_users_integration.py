import csv

from django.core.files.temp import NamedTemporaryFile
from django.core.management import call_command
from django.urls import reverse

from openwisp_users.tests.test_admin import TestBasicUsersIntegration
from openwisp_utils.tests import capture_stdout

from ..utils import load_model
from .mixins import GetEditFormInlineMixin

RadiusToken = load_model('RadiusToken')
RegisteredUser = load_model('RegisteredUser')


class TestUsersIntegration(GetEditFormInlineMixin, TestBasicUsersIntegration):
    """
    tests integration with openwisp_users
    """

    is_integration_test = True

    def test_radiustoken_inline(self):
        admin = self._create_admin()
        self.client.force_login(admin)
        user = self._create_user()
        org = self._get_org()
        self._create_org_user(organization=org, user=user)
        params = user.__dict__
        params.pop('phone_number')
        params.pop('password', None)
        params.pop('_password', None)
        params.pop('bio', None)
        params.pop('last_login', None)
        params.pop('password_updated', None)
        params.pop('birth_date', None)
        params = self._additional_params_pop(params)
        params.update(self._get_user_edit_form_inline_params(user, org))
        url = reverse(f'admin:{self.app_label}_user_change', args=[user.pk])
        response = self.client.get(
            url,
        )
        self.assertContains(response, 'id="id_radius_token-__prefix__-organization"')
        self.assertNotContains(response, 'id="id_radius_token-__prefix__-key"')

        # Create a radius token
        params.update(
            {
                'radius_token-0-organization': str(org.id),
                'radius_token-0-user': str(user.id),
                'radius_token-0-can_auth': True,
                'radius_token-TOTAL_FORMS': '1',
                '_continue': True,
            }
        )
        response = self.client.post(url, params, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(RadiusToken.objects.count(), 1)
        radius_token = user.radius_token.key
        self.assertContains(
            response,
            (
                '<input type="text" name="radius_token-0-key"'
                f' value="{radius_token}"'
                ' class="readonly vTextField" readonly maxlength="40"'
                ' id="id_radius_token-0-key">'
            ),
            html=True,
        )

        # Delete user radius token
        params.update(
            {
                'radius_token-0-DELETE': 'on',
                'radius_token-INITIAL_FORMS': '1',
                'radius_token-0-key': radius_token,
            }
        )
        response = self.client.post(url, params, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(RadiusToken.objects.count(), 0)

    @capture_stdout()
    def test_export_users_command(self):
        temp_file = NamedTemporaryFile(delete=False)
        user = self._create_org_user().user
        RegisteredUser.objects.create(
            user=user, method='mobile_phone', is_verified=False
        )
        with self.assertNumQueries(1):
            call_command('export_users', filename=temp_file.name)

        with open(temp_file.name, 'r') as file:
            csv_reader = csv.reader(file)
            csv_data = list(csv_reader)

        self.assertEqual(len(csv_data), 2)
        self.assertIn('registered_user.method', csv_data[0])
        self.assertIn('registered_user.is_verified', csv_data[0])
        self.assertEqual(csv_data[1][-2], 'mobile_phone')
        self.assertEqual(csv_data[1][-1], 'False')


del TestBasicUsersIntegration
