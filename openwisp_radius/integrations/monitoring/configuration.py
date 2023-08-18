from copy import deepcopy

from django.utils.translation import gettext_lazy as _
from openwisp_monitoring.monitoring.configuration import DEFAULT_COLORS

from openwisp_radius.registration import REGISTRATION_METHOD_CHOICES

user_signups_chart_traces = {'total': 'lines'}
user_signups_chart_order = ['total']
user_signups_chart_summary_labels = [_('Total new users')]

for (method, label) in REGISTRATION_METHOD_CHOICES:
    if method == '':
        method = 'unspecified'
    user_signups_chart_traces[method] = 'stackedbar'
    user_signups_chart_summary_labels.append(
        _('New %(label)s users' % {"label": label})
    )
    user_signups_chart_order.append(method)


user_singups_chart_config = {
    'type': 'stackedbar+lines',
    'trace_type': user_signups_chart_traces,
    'trace_order': user_signups_chart_order,
    'title': _('User Registration'),
    'label': _('User Registration'),
    'description': _('Daily user registration grouped by registration method'),
    'summary_labels': user_signups_chart_summary_labels,
    'order': 240,
    'unit': '',
    'calculate_total': True,
    'query': {
        'influxdb': (
            "SELECT COUNT(DISTINCT(user_id)) FROM "
            " {key} WHERE time >= '{time}' {end_date} {organization_id}"
            " GROUP BY time(1d), method"
        )
    },
    'query_default_param': {
        'organization_id': '',
    },
    'colors': [
        DEFAULT_COLORS[7],
        DEFAULT_COLORS[0],
        DEFAULT_COLORS[1],
        DEFAULT_COLORS[2],
        DEFAULT_COLORS[3],
        DEFAULT_COLORS[4],
        DEFAULT_COLORS[5],
    ],
}

cumulative_user_singups_chart_config = deepcopy(user_singups_chart_config)
cumulative_user_singups_chart_config['query']['influxdb'] = (
    "SELECT CUMULATIVE_SUM(COUNT(DISTINCT(user_id))) FROM "
    " {key} WHERE time >= '{time}' {end_date} {organization_id}"
    " GROUP BY time(1d), method"
)
cumulative_user_singups_chart_config['summary_query'] = {
    'influxdb': user_singups_chart_config['query']['influxdb']
}
cumulative_user_singups_chart_config['title'] = _('Total Registered Users')
cumulative_user_singups_chart_config['label'] = _('Total Registered Users')
cumulative_user_singups_chart_config['order'] = 241


RADIUS_METRICS = {
    'user_signups': {
        'label': _('User Registration'),
        'name': 'User Registration',
        'key': 'user_signups',
        'field_name': 'user_id',
        'charts': {
            'user_signups': user_singups_chart_config,
            'tot_user_signups': cumulative_user_singups_chart_config,
        },
    },
    'radius_acc': {
        'label': _('RADIUS Accounting'),
        'name': '{name}',
        'key': 'radius_acc',
        'field_name': 'input_octets',
        'related_fields': ['output_octets', 'username'],
        'charts': {
            'radius_traffic': {
                'type': 'stackedbar+lines',
                'calculate_total': True,
                'trace_type': {
                    'download': 'stackedbar',
                    'upload': 'stackedbar',
                    'total': 'lines',
                },
                'trace_order': ['total', 'download', 'upload'],
                'title': _('RADIUS Sessions Traffic'),
                'label': _('RADIUS Traffic'),
                'description': _(
                    'RADIUS Network traffic (total, download and upload).'
                ),
                'summary_labels': [
                    _('Total traffic'),
                    _('Total download traffic'),
                    _('Total upload traffic'),
                ],
                'unit': 'adaptive_prefix+B',
                'order': 241,
                'query': {
                    'influxdb': (
                        "SELECT SUM(output_octets) / 1000000000 AS upload, "
                        "SUM(input_octets) / 1000000000 AS download FROM {key} "
                        "WHERE time >= '{time}' {end_date} "
                        "AND content_type = '{content_type}' "
                        "AND object_id = '{object_id}' "
                        "GROUP BY time(1d)"
                    )
                },
                'colors': [
                    DEFAULT_COLORS[7],
                    DEFAULT_COLORS[0],
                    DEFAULT_COLORS[1],
                ],
            },
            'rad_session': {
                'type': 'stackedbar+lines',
                'calculate_total': True,
                'fill': 'none',
                'trace_type': user_signups_chart_traces,
                'trace_order': user_signups_chart_order,
                'title': _('Unique RADIUS Session Count'),
                'label': _('RADIUS Session Count'),
                'description': _(
                    'RADIUS Network traffic (total, download and upload).'
                ),
                'summary_labels': user_signups_chart_summary_labels,
                'unit': '',
                'order': 242,
                'query': {
                    'influxdb': (
                        "SELECT COUNT(DISTINCT(username)) FROM {key} "
                        "WHERE time >= '{time}' {end_date} "
                        "AND content_type = '{content_type}' "
                        "AND object_id = '{object_id}' "
                        "GROUP by time(1d), method"
                    )
                },
                'query_default_param': {
                    'organization_id': '',
                    'location_id': '',
                },
                'colors': user_singups_chart_config['colors'],
            },
        },
    },
    'gen_radius_acc': {
        'label': _('General RADIUS Accounting'),
        'name': 'General RADIUS Accounting',
        'key': 'radius_acc',
        'field_name': 'input_octets',
        'related_fields': ['output_octets'],
        'charts': {
            'gen_rad_traffic': {
                'type': 'stackedbar+lines',
                'calculate_total': True,
                'fill': 'none',
                'trace_type': {
                    'download': 'stackedbar',
                    'upload': 'stackedbar',
                    'total': 'lines',
                },
                'trace_order': ['total', 'download', 'upload'],
                'title': _('Total RADIUS Sessions Traffic'),
                'label': _('General RADIUS Traffic'),
                'description': _(
                    'RADIUS Network traffic (total, download and upload).'
                ),
                'summary_labels': [
                    _('Total traffic'),
                    _('Total download traffic'),
                    _('Total upload traffic'),
                ],
                'unit': 'adaptive_prefix+B',
                'order': 242,
                'query': {
                    'influxdb': (
                        "SELECT SUM(output_octets) / 1000000000 AS upload, "
                        "SUM(input_octets) / 1000000000 AS download FROM {key} "
                        "WHERE time >= '{time}' {end_date} {organization_id} "
                        "{location_id} GROUP BY time(1d)"
                    )
                },
                'query_default_param': {
                    'organization_id': '',
                    'location_id': '',
                },
                'colors': [
                    DEFAULT_COLORS[7],
                    DEFAULT_COLORS[0],
                    DEFAULT_COLORS[1],
                ],
            },
            'gen_rad_session': {
                'type': 'stackedbar+lines',
                'calculate_total': True,
                'fill': 'none',
                'trace_type': user_signups_chart_traces,
                'trace_order': user_signups_chart_order,
                'title': _('Unique RADIUS Session Count'),
                'label': _('General RADIUS Session Count'),
                'description': _(
                    'RADIUS Network traffic (total, download and upload).'
                ),
                'summary_labels': user_signups_chart_summary_labels,
                'unit': '',
                'order': 243,
                'query': {
                    'influxdb': (
                        "SELECT COUNT(DISTINCT(username)) FROM {key} "
                        "WHERE time >= '{time}' {end_date} {organization_id} "
                        "{location_id} GROUP by time(1d), method"
                    )
                },
                'query_default_param': {
                    'organization_id': '',
                    'location_id': '',
                },
                'colors': user_singups_chart_config['colors'],
            },
        },
    },
}
