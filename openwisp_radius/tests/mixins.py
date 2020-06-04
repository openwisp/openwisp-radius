import os

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase

from openwisp_users.models import Organization

from ..utils import load_model
from . import CallCommandMixin as BaseCallCommandMixin
from . import CreateRadiusObjectsMixin as BaseCreateRadiusObjectsMixin
from . import PostParamsMixin as BasePostParamsMixin

User = get_user_model()
RadiusBatch = load_model('RadiusBatch')


class CreateRadiusObjectsMixin(BaseCreateRadiusObjectsMixin):
    def _create_org(self, **kwargs):
        options = dict(name='default', slug='default')
        options.update(kwargs)
        try:
            org = Organization.objects.get(**options)
        except Organization.DoesNotExist:
            org = Organization(**options)
            org.full_clean()
            org.save()
        return org

    def _get_defaults(self, options, model=None):
        if not model or hasattr(model, 'organization'):
            options.update({'organization': self._create_org()})
        return super()._get_defaults(options, model)

    def _create_user(self, **kwargs):
        user = super()._create_user(**kwargs)
        org = self._create_org()
        org.add_user(user)
        return user


class CallCommandMixin(BaseCallCommandMixin):
    def _call_command(self, command, **kwargs):
        Organization.objects.get_or_create(name='test-organization')
        options = dict(organization='test-organization')
        kwargs.update(options)
        super()._call_command(command, **kwargs)


class PostParamsMixin(BasePostParamsMixin):
    def _get_post_defaults(self, options, model=None):
        if not model or hasattr(model, 'organization'):
            options.update({'organization': str(self._create_org().pk)})
        return super()._get_post_defaults(options, model)


class DefaultOrgMixin(object):
    def setUp(self):
        self.default_org = Organization.objects.get(slug='default')
        super().setUp()


class ApiTokenMixin(BasePostParamsMixin):
    def setUp(self):
        super().setUp()
        org = self.default_org
        rad = self.default_org.radius_settings
        self.auth_header = 'Bearer {0} {1}'.format(org.pk, rad.token)
        self.token_querystring = '?token={0}&uuid={1}'.format(rad.token, str(org.pk))


class BaseTestCase(DefaultOrgMixin, CreateRadiusObjectsMixin, TestCase):
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
