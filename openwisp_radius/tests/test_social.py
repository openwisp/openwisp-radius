from allauth.socialaccount.models import SocialAccount
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse
from rest_framework.authtoken.models import Token

from ..utils import load_model
from .mixins import ApiTokenMixin, BaseTestCase

RadiusToken = load_model('RadiusToken')

User = get_user_model()


class TestSocial(ApiTokenMixin, BaseTestCase):
    view_name = 'radius:redirect_cp'

    def get_url(self):
        return reverse(self.view_name, args=[self.default_org.slug])

    def test_redirect_cp_404(self):
        u = self._create_social_user()
        self.client.force_login(u)
        r = self.client.get(reverse(self.view_name, args=['wrong']), {'cp': 'test'})
        self.assertEqual(r.status_code, 404)

    def _create_social_user(self):
        u = User.objects.create(username='socialuser', email='test@test.org')
        u.set_unusable_password()
        u.save()
        sa = SocialAccount(user=u, provider='facebook', uid='12345', extra_data='{}')
        sa.full_clean()
        sa.save()
        return u

    def test_redirect_cp_400(self):
        url = self.get_url()
        r = self.client.get(url)
        self.assertEqual(r.status_code, 400)

    def test_redirect_cp_403(self):
        url = self.get_url()
        r = self.client.get(url, {'cp': 'http://wifi.openwisp.org/cp'})
        self.assertEqual(r.status_code, 403)

    def test_redirect_cp_301(self):
        user = self._create_social_user()
        self.client.force_login(user)
        url = self.get_url()
        r = self.client.get(url, {'cp': 'http://wifi.openwisp.org/cp'})
        self.assertEqual(r.status_code, 302)
        qs = Token.objects.filter(user=user)
        rs = RadiusToken.objects.filter(user=user, organization=self._get_org())
        self.assertEqual(qs.count(), 1)
        self.assertEqual(rs.count(), 1)
        token = qs.first()
        rad_token = rs.first()
        querystring = (
            f'username={user.username}&token={token.key}&'
            f'radius_user_token={rad_token.key}'
        )
        self.assertIn(querystring, r.url)
        user = User.objects.filter(username='socialuser').first()
        self.assertTrue(user.is_member(self.default_org))
        try:
            reg_user = user.registered_user
        except ObjectDoesNotExist:
            self.fail('RegisteredUser instance not found')
        self.assertEqual(reg_user.method, 'social_login')
        # social login is not a legally valid identity verification method
        # so this should be always False when users sign up with this method
        self.assertFalse(reg_user.is_verified)

    def test_authorize_using_radius_user_token_200(self):
        self.test_redirect_cp_301()
        rad_token = RadiusToken.objects.filter(user__username='socialuser').first()
        self.assertIsNotNone(rad_token)
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': 'socialuser', 'password': rad_token.key},
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 200)

    def test_authorize_using_user_token_403(self):
        self.test_redirect_cp_301()
        rad_token = RadiusToken.objects.filter(user__username='socialuser').first()
        self.assertIsNotNone(rad_token)
        response = self.client.post(
            reverse('radius:authorize'),
            {'username': 'socialuser', 'password': 'WRONG'},
            HTTP_AUTHORIZATION=self.auth_header,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.data)
