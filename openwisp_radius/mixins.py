from django_freeradius.tests import CallCommandMixin as BaseCallCommandMixin
from django_freeradius.tests import CreateRadiusObjectsMixin as BaseCreateRadiusObjectsMixin
from django_freeradius.tests import PostParamsMixin as BasePostParamsMixin

from openwisp_users.models import Organization


class CreateRadiusObjectsMixin(BaseCreateRadiusObjectsMixin):
    def _create_org(self, **kwargs):
        options = dict(name='default',
                       slug='default')
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
        super(CallCommandMixin, self)._call_command(command, **kwargs)


class PostParamsMixin(BasePostParamsMixin):
    def _get_post_defaults(self, options, model=None):
        if not model or hasattr(model, 'organization'):
            options.update({'organization': str(self._create_org().pk)})
        return super()._get_post_defaults(options, model)
