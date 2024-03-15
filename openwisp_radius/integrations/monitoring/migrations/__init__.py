import swapper

from ..configuration import RADIUS_METRICS


def create_general_metrics(apps, schema_editor):
    Chart = swapper.load_model('monitoring', 'Chart')
    Metric = swapper.load_model('monitoring', 'Metric')

    metric, created = Metric._get_or_create(
        configuration='user_signups',
        name='User SignUps',
        key='user_signups',
        object_id=None,
        content_type=None,
    )
    if created:
        for configuration in metric.config_dict['charts'].keys():
            chart = Chart(metric=metric, configuration=configuration)
            chart.full_clean()
            chart.save()

    metric, created = Metric._get_or_create(
        configuration='tot_user_signups',
        name='Total User SignUps',
        key='tot_user_signups',
        object_id=None,
        content_type=None,
    )
    if created:
        for configuration in metric.config_dict['charts'].keys():
            chart = Chart(metric=metric, configuration=configuration)
            chart.full_clean()
            chart.save()

    metric, created = Metric._get_or_create(
        configuration='gen_radius_acc',
        name='RADIUS Accounting',
        key='radius_acc',
        object_id=None,
        content_type=None,
    )

    if created:
        for configuration in metric.config_dict['charts'].keys():
            chart = Chart(metric=metric, configuration=configuration)
            chart.full_clean()
            chart.save()


def delete_general_metrics(apps, schema_editor):
    Metric = apps.get_model('monitoring', 'Metric')
    Metric.objects.filter(
        content_type__isnull=True, object_id__isnull=True, key__in=RADIUS_METRICS.keys()
    ).delete()
