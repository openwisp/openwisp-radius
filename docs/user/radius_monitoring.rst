.. _integration_with_openwisp_monitoring:

Integration with OpenWISP Monitoring
====================================

OpenWISP RADIUS includes an optional Django sub-app that adds integration
with :doc:`OpenWISP Monitoring </monitoring/index>` to provide RADIUS
metrics.

.. image:: ../images/radius-dashboard-charts.png
    :alt: RADIUS session dashboard charts

RADIUS metrics
--------------

1. User registrations
~~~~~~~~~~~~~~~~~~~~~

.. image:: ../images/user-registration-chart.png
    :alt: User registration chart

This chart shows number of users signed up using different registration
methods.

2. Total user registrations
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. image:: ../images/total-user-registration-chart.png
    :alt: Total user registration chart

This chart shows total users registered using different registration
methods in the system on a given date.

3. Unique RADIUS Sessions
~~~~~~~~~~~~~~~~~~~~~~~~~

.. image:: ../images/unique-radius-session-chart.png
    :alt: Unique RADIUS session chart

This chart shows unique RADIUS sessions. It is helpful to know how many
unique users has used the system in a given time.

4. RADIUS traffic
~~~~~~~~~~~~~~~~~

.. image:: ../images/radius-traffic-chart.png
    :alt: RADIUS traffic chart

This chart shows traffic from active and closed sessions. If a collection
is missed, the next successful collection shows the accumulated traffic at
that time, rather than in the periods when it occurred.

Enabling RADIUS metrics in Django project
-----------------------------------------

.. include:: /partials/settings-note.rst

You can enable the monitoring integration by including
``openwisp_radius.integrations.monitoring`` in ``INSTALLED_APPS`` of your
Django project's settings as following:

.. code-block:: python

    # In your_project/settings.py

    INSTALLED_APPS.append("openwisp_radius.integrations.monitoring")
    CELERY_BEAT_SCHEDULE.update(
        {
            "write_user_registration_metrics": {
                "task": "openwisp_radius.integrations.monitoring.tasks.write_user_registration_metrics",
                "schedule": timedelta(hours=1),
                "args": None,
                "relative": True,
            },
            "reconcile_radius_traffic": {
                "task": "openwisp_radius.integrations.monitoring.tasks.reconcile_radius_traffic",
                "schedule": timedelta(hours=1),
            },
        }
    )

.. note::

    Ensure your Django project is correctly configured to utilize OpenWISP
    Monitoring. For production environments, it is advisable to deploy
    OpenWISP using :doc:`Ansible OpenWISP </ansible/index>` or
    :doc:`Docker OpenWISP </docker/index>`, as they simplify the
    deployment process considerably.

.. important::

    If you are registering a :ref:`"registration method"
    <openwisp_radius_register_registration_method>` in any other Django
    application, then ``openwisp_radius.integrations.monitoring`` should
    come after that app in the ``INSTALLED_APPS``. Otherwise, the
    registration method would not appear in the chart.

``write_user_registration_metrics`` collects registrations and then
attempts traffic reconciliation, even if registration collection fails.
The separate ``reconcile_radius_traffic`` schedule also triggers traffic
reconciliation at its configured interval.

Use a shared Django cache accessible to every worker and management
command. A process-local cache is not suitable for production.

Recovery and accuracy limits
----------------------------

Traffic collection uses aggregate counters rather than tracking each
session's reported traffic. This keeps collection inexpensive, with the
following limits:

- A counter reset in one session can hide growth in another session in the
  same group. Decreases are logged and never produce negative chart
  traffic.
- Moving retained accounting rows to another ``Called-Station-ID``,
  including with ``convert_called_station_id``, can report their traffic
  again under the new group.
- Monitoring normally queues metric writes. Successful submission does not
  confirm persistence. Losing the cache before a queued checkpoint reaches
  the time-series database can restore an older baseline and duplicate or
  miss traffic. Collection does not guarantee exactly-once delivery or
  atomic updates across SQL, cache and the time-series database.
- The shared cache lock prevents ordinary overlapping runs, but a worker
  stalled beyond its six-hour lease can overlap a later run. Cache item
  limits can also prevent saving the state, stopping collection and
  cleanup rather than allowing cleanup without its prepared adjustment.
- Empty observations refresh an activation checkpoint. Recovery still
  depends on checkpoints remaining within time-series retention. If the
  schedule stops long enough for all checkpoints to expire and the cache
  is lost, collection can mistake the next observation for initialization.

Checkpoint read failures defer the affected group without treating it as a
new group. Other groups with cached baselines can continue reporting.
Failure to recover whether collection was initialized still defers the
whole run.

The upgrade migration submits open-session traffic and initializes
aggregate baselines automatically. A session closing between the legacy
job drain and the snapshot can be missed; an already reported session
reopening before the snapshot can be counted again. A failed migration may
already have submitted some points. Investigate its logged snapshot time,
submitted totals and available accounting and metric history before
retrying: a fresh snapshot is not a safe automatic retry.
