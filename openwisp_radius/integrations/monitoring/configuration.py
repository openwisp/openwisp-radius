from copy import deepcopy

from django.utils.translation import gettext_lazy as _
from openwisp_monitoring.monitoring.configuration import DEFAULT_COLORS

from openwisp_radius.registration import REGISTRATION_METHOD_CHOICES

_flux_range = (
    'import "date"\n{timezone_import}from(bucket: "{bucket}")'
    " |> range(start: {time_start}{end_range})"
    ' |> filter(fn: (r) => r._measurement == "{key}")'
)
_flux_object_filters = "{content_type_filter}{object_id_filter}"
_flux_organization_filters = "{organization_id_filter}{location_id_filter}"
_flux_field_group = ' |> group(columns: ["_field"])'
_flux_method_group = ' |> group(columns: ["method"])'
_flux_method_summary_group = ' |> group(columns: ["method", "_start", "_stop"])'
_flux_summary_time = " |> map(fn: (r) => ({{r with _time: r._start}}))"
_flux_truncate_time = (
    " |> map(fn: (r) => ({{r with _time: date.truncate(t: r._time, "
    "unit: {window}{window_timezone})}}))"
)
# selectors keep the other tags of the point, which would end up in the trace
# name, hence these records are rebuilt explicitly
_flux_method_projection = (
    " |> map(fn: (r) => ({{_time: date.truncate(t: r._time, "
    "unit: {window}{window_timezone}), _value: r._value, method: r.method}}))"
)
_flux_method_summary_projection = (
    " |> map(fn: (r) => ({{_time: r._start, _value: r._value, method: r.method}}))"
)


def _flux_window(function):
    return (
        " |> aggregateWindow(every: {window}, fn: " + function + ', timeSrc: "_start"'
        "{window_timezone})" + _flux_truncate_time
    )


def _flux_signups(function, summary=False):
    query = (
        _flux_range
        + "{organization_id_filter}"
        + ' |> filter(fn: (r) => r._field == "count")'
    )
    if summary:
        query += _flux_method_summary_group + " |> {}()".format(function)
        if function == "last":
            return query + _flux_method_summary_projection
        return query + _flux_summary_time
    query += _flux_method_group + (
        " |> aggregateWindow(every: {window}, fn: " + function + ', timeSrc: "_start"'
        ", createEmpty: true{window_timezone})"
    )
    if function == "last":
        # Flux does not provide the linear fill of InfluxDB 1
        return (
            query
            + ' |> fill(column: "_value", usePrevious: true)'
            + _flux_method_projection
        )
    return query + _flux_truncate_time


def _flux_traffic(filters, summary=False):
    query = (
        _flux_range
        + filters
        + " |> filter(fn: (r) => r._field =~ /^(input_octets|output_octets)$/)"
        + _flux_field_group
    )
    query += " |> sum()" if summary else _flux_window("sum")
    return query + (
        " |> map(fn: (r) => ({{r with "
        '_field: if r._field == "output_octets" then "upload" else "download", '
        "_value: float(v: r._value) / 1000000000.0}}))"
    )


def _flux_sessions(filters, summary=False):
    query = _flux_range + filters + ' |> filter(fn: (r) => r._field == "username")'
    if summary:
        return (
            query
            + _flux_method_summary_group
            + ' |> unique(column: "_value")'
            + " |> count()"
            + _flux_summary_time
        )
    return (
        query
        + _flux_method_group
        + " |> window(every: {window}, createEmpty: true{window_timezone})"
        + ' |> unique(column: "_value")'
        + " |> count()"
        + " |> map(fn: (r) => ({{r with _time: date.truncate(t: r._start, "
        "unit: {window}{window_timezone})}}))"
    )


user_signups_chart_traces = {"total": "lines"}
user_signups_chart_order = ["total"]
user_signups_chart_trace_labels = {
    "total": _("Total"),
}
user_signups_chart_summary_labels = [_("Total new users")]

for method, label in REGISTRATION_METHOD_CHOICES:
    if method == "":
        method = "unspecified"
    user_signups_chart_traces[method] = "stackedbar"
    user_signups_chart_summary_labels.append(
        _("New %(label)s users" % {"label": label})
    )
    user_signups_chart_trace_labels[method] = label
    user_signups_chart_order.append(method)


user_singups_chart_config = {
    "type": "stackedbar+lines",
    "trace_type": user_signups_chart_traces,
    "trace_order": user_signups_chart_order,
    "title": _("User Registrations"),
    "label": _("User Registrations"),
    "description": _("Daily user registrations grouped by registration method"),
    "summary_labels": user_signups_chart_summary_labels,
    "trace_labels": user_signups_chart_trace_labels,
    "order": 240,
    "__all__": True,
    "unit": "",
    "calculate_total": True,
    "query": {
        "influxdb": (
            "SELECT SUM(count) FROM "
            " {key} WHERE time >= '{time}' {end_date} {organization_id}"
            " GROUP BY time(1d), method"
        ),
        "influxdb2": _flux_signups("sum"),
    },
    "summary_query": {"influxdb2": _flux_signups("sum", summary=True)},
    "query_default_param": {
        "organization_id": "",
    },
    "colors": [
        DEFAULT_COLORS[7],
        "#8C564B",
        "#17BECF",
        "#9467BD",
        "#D62728",
        "#E377C2",
        "#1F77B4",
        "#2CA02C",
        "#BCBD22",
    ],
}

total_user_singups_chart_config = deepcopy(user_singups_chart_config)
total_user_singups_chart_config["query"]["influxdb"] = (
    "SELECT LAST(count) FROM "
    " {key} WHERE time >= '{time}' {end_date} {organization_id}"
    " GROUP BY time(1d), method FILL(linear)"
)
total_user_singups_chart_config["query"]["influxdb2"] = _flux_signups("last")
total_user_singups_chart_config["summary_query"] = {
    "influxdb2": _flux_signups("last", summary=True)
}
total_user_singups_chart_config["title"] = _("Total Registered Users")
total_user_singups_chart_config["label"] = _("Total Registered Users")
total_user_singups_chart_config["filter__all__"] = True
total_user_singups_chart_config["order"] = 241


RADIUS_METRICS = {
    "user_signups": {
        "label": _("User Registrations"),
        "name": "User Registrations",
        "key": "user_signups",
        "field_name": "count",
        "charts": {
            "user_signups": user_singups_chart_config,
        },
    },
    "tot_user_signups": {
        "label": _("Total User Registrations"),
        "name": "Total User Registrations",
        "key": "tot_user_signups",
        "field_name": "count",
        "charts": {
            "tot_user_signups": total_user_singups_chart_config,
        },
    },
    "radius_acc": {
        "label": _("RADIUS Accounting"),
        "name": "{name}",
        "key": "radius_acc",
        "field_name": "input_octets",
        "related_fields": ["output_octets", "username"],
        "charts": {
            "radius_traffic": {
                "type": "stackedbar+lines",
                "calculate_total": True,
                "trace_type": {
                    "download": "stackedbar",
                    "upload": "stackedbar",
                    "total": "lines",
                },
                "trace_order": ["total", "download", "upload"],
                "title": _("RADIUS Sessions Traffic"),
                "label": _("RADIUS Traffic"),
                "description": _(
                    "RADIUS Network traffic (total, download and upload)."
                ),
                "summary_labels": [
                    _("Total traffic"),
                    _("Total download traffic"),
                    _("Total upload traffic"),
                ],
                "unit": "adaptive_prefix+B",
                "order": 221,
                "query": {
                    "influxdb": (
                        "SELECT SUM(output_octets) / 1000000000 AS upload, "
                        "SUM(input_octets) / 1000000000 AS download FROM {key} "
                        "WHERE time >= '{time}' {end_date} "
                        "AND content_type = '{content_type}' "
                        "AND object_id = '{object_id}' "
                        "GROUP BY time(1d)"
                    ),
                    "influxdb2": _flux_traffic(_flux_object_filters),
                },
                "summary_query": {
                    "influxdb2": _flux_traffic(_flux_object_filters, summary=True)
                },
                "colors": [
                    DEFAULT_COLORS[7],
                    DEFAULT_COLORS[0],
                    DEFAULT_COLORS[1],
                ],
            },
            "rad_session": {
                "type": "stackedbar+lines",
                "calculate_total": True,
                "fill": "none",
                "trace_type": user_signups_chart_traces,
                "trace_order": user_signups_chart_order,
                "title": _("Unique RADIUS Sessions"),
                "label": _("Unique RADIUS Sessions"),
                "description": _(
                    "RADIUS Network traffic (total, download and upload)."
                ),
                "summary_labels": user_signups_chart_summary_labels,
                "trace_labels": user_signups_chart_trace_labels,
                "unit": "",
                "order": 222,
                "query": {
                    "influxdb": (
                        "SELECT COUNT(DISTINCT(username)) FROM {key} "
                        "WHERE time >= '{time}' {end_date} "
                        "AND content_type = '{content_type}' "
                        "AND object_id = '{object_id}' "
                        "GROUP by time(1d), method"
                    ),
                    "influxdb2": _flux_sessions(_flux_object_filters),
                },
                "summary_query": {
                    "influxdb2": _flux_sessions(_flux_object_filters, summary=True)
                },
                "query_default_param": {
                    "organization_id": "",
                    "location_id": "",
                },
                "colors": user_singups_chart_config["colors"],
            },
        },
    },
    "gen_radius_acc": {
        "label": _("General RADIUS Accounting"),
        "name": "General RADIUS Accounting",
        "key": "radius_acc",
        "field_name": "input_octets",
        "related_fields": ["output_octets"],
        "charts": {
            "gen_rad_traffic": {
                "type": "stackedbar+lines",
                "calculate_total": True,
                "fill": "none",
                "trace_type": {
                    "download": "stackedbar",
                    "upload": "stackedbar",
                    "total": "lines",
                },
                "trace_order": ["total", "download", "upload"],
                "title": _("Traffic of RADIUS Sessions"),
                "label": _("General RADIUS Traffic"),
                "description": _(
                    "RADIUS Network traffic (total, download and upload)."
                ),
                "summary_labels": [
                    _("Total traffic"),
                    _("Total download traffic"),
                    _("Total upload traffic"),
                ],
                "unit": "adaptive_prefix+B",
                "order": 242,
                "query": {
                    "influxdb": (
                        "SELECT SUM(output_octets) / 1000000000 AS upload, "
                        "SUM(input_octets) / 1000000000 AS download FROM {key} "
                        "WHERE time >= '{time}' {end_date} {organization_id} "
                        "{location_id} GROUP BY time(1d)"
                    ),
                    "influxdb2": _flux_traffic(_flux_organization_filters),
                },
                "summary_query": {
                    "influxdb2": _flux_traffic(_flux_organization_filters, summary=True)
                },
                "query_default_param": {
                    "organization_id": "",
                    "location_id": "",
                },
                "colors": [
                    DEFAULT_COLORS[7],
                    DEFAULT_COLORS[0],
                    DEFAULT_COLORS[1],
                ],
            },
            "gen_rad_session": {
                "type": "stackedbar+lines",
                "calculate_total": True,
                "fill": "none",
                "trace_type": user_signups_chart_traces,
                "trace_order": user_signups_chart_order,
                "title": _("Unique RADIUS Sessions"),
                "label": _("General RADIUS Sessions"),
                "description": _(
                    "RADIUS Network traffic (total, download and upload)."
                ),
                "summary_labels": user_signups_chart_summary_labels,
                "trace_labels": user_signups_chart_trace_labels,
                "unit": "",
                "order": 243,
                "query": {
                    "influxdb": (
                        "SELECT COUNT(DISTINCT(username)) FROM {key} "
                        "WHERE time >= '{time}' {end_date} {organization_id} "
                        "{location_id} GROUP by time(1d), method"
                    ),
                    "influxdb2": _flux_sessions(_flux_organization_filters),
                },
                "summary_query": {
                    "influxdb2": _flux_sessions(
                        _flux_organization_filters, summary=True
                    )
                },
                "query_default_param": {
                    "organization_id": "",
                    "location_id": "",
                },
                "colors": user_singups_chart_config["colors"],
            },
        },
    },
}
