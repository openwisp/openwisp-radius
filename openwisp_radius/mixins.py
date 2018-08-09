from django_freeradius.tests import ApiParamsMixin as BaseApiParamsMixin
from django_freeradius.tests import CreateObjectsMixin as BaseCreateObjectsMixin
from django_freeradius.tests.utils import CallCommandMixin as BaseCallCommandMixin

from openwisp_users.models import Organization


class CreateObjectsMixin(BaseCreateObjectsMixin):
    def _create_org(self, **kwargs):
        options = dict(name='test-organization')
        options.update(kwargs)
        org = Organization(**options)
        org.save()
        return org

    def _get_extra_fields(self, **kwargs):
        org = Organization.objects.get_or_create(name='test-organization')
        options = dict(organization=org[0])
        return options


class CallCommandMixin(BaseCallCommandMixin):
    def _call_command(self, command, **kwargs):
        Organization.objects.get_or_create(name='test-organization')
        options = dict(organization='test-organization')
        kwargs.update(options)
        super(CallCommandMixin, self)._call_command(command, **kwargs)


class ApiParamsMixin(BaseApiParamsMixin):
    def _get_extra_params(self, **kwargs):
        org = Organization.objects.get_or_create(name='test-organization')
        options = dict(organization=str(org[0].pk))
        options.update(**kwargs)
        return options
