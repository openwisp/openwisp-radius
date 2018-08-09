from django_freeradius.api.views import BatchView as BaseBatchView
from django_freeradius.api.views import accounting, authorize, postauth

from openwisp_users.models import Organization


class BatchView(BaseBatchView):
    def _create_batch(self, serializer, **kwargs):
        org_id = serializer.data.get('organization')
        org = Organization.objects.get(pk=org_id)
        options = dict(organization=org)
        options.update(kwargs)
        return super(BatchView, self)._create_batch(serializer, **options)


batch = BatchView.as_view()
