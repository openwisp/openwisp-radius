# Deferred work

## Upstream Monitoring: exact tags for individual metric points

Deferred by user decision while handling [RADIUS PR #834](https://github.com/openwisp/openwisp-radius/pull/834). Revisit in `openwisp-monitoring`; do not work around it by modifying Monitoring's internal tag fields from RADIUS.

Monitoring's `Metric._get_or_create()` merges supplied extra tags into stored tags, and `Metric.write()` uses the resulting tags. Omitting a tag does not remove an old value. For example, traffic reported after removing a device's location can still appear under its previous location. Unmatched shared-accounting traffic can likewise retain an old organization tag and appear under the wrong organization.

Verified against Monitoring master revision `1f86a1235ab17927ad6b3362b6797f8f974cdf9e`, in `openwisp_monitoring/monitoring/base/models.py`. The installed Monitoring dependency has the same merge and write behavior.

Proposed follow-up:

- Add an optional exact-point-tags operation to Monitoring's public write API, supported by `Metric.batch_write()`, while preserving existing callers' behavior.
- Apply the supplied tags only to the individual point without changing the metric's stored tags, and retain Monitoring's validation, alert, and submission handling.
- Use that API from the RADIUS integration once available.
- Test location removal and unmatched shared-accounting traffic after an organization-tagged write. New traffic must remain in the appropriate device and global totals without being attributed to the previous location or organization; historical points must remain unchanged.

Related review threads:

- [Removed location tag remains on subsequent points](https://github.com/openwisp/openwisp-radius/pull/834#discussion_r4691272667).
- [Old organization tag remains on unmatched shared traffic](https://github.com/openwisp/openwisp-radius/pull/834#discussion_r4693927200).

Deferral records a known correctness concern, not a fix or review clearance.
