from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from openwisp_monitoring.db import timeseries_db
from swapper import load_model

from openwisp_radius.integrations.monitoring import tasks
from openwisp_radius.integrations.monitoring.utils import sha1_hash
from openwisp_radius.utils import MAC_ADDRESS_PATTERN, sanitize_mac_address

RadiusAccounting = load_model("openwisp_radius", "RadiusAccounting")


class Command(BaseCommand):
    """
    Rebuild RADIUS accounting metrics missed by the NAS-Reboot bulk update path.

    See https://github.com/openwisp/openwisp-radius/issues/734.
    TODO: remove in version 1.4.
    """

    help = "Private command to rebuild monitoring metrics for closed RADIUS sessions."

    def add_arguments(self, parser):
        parser.add_argument(
            "--commit",
            action="store_true",
            help="Write metrics. Without this flag the command only reports the count.",
        )
        parser.add_argument(
            "--start",
            help=(
                "Only process sessions with stop_time greater than or equal "
                "to this date."
            ),
        )
        parser.add_argument(
            "--end",
            help=(
                "Only process sessions with stop_time lower than or equal "
                "to this date."
            ),
        )
        parser.add_argument(
            "--chunk-size",
            type=int,
            default=1000,
            help="Number of sessions fetched per database batch.",
        )

    def handle(self, *args, **options):
        queryset = RadiusAccounting.objects.filter(
            stop_time__isnull=False,
            terminate_cause="NAS-Reboot",
        )
        if options["start"]:
            queryset = queryset.filter(
                stop_time__gte=self._parse_datetime(options["start"], "start")
            )
        if options["end"]:
            queryset = queryset.filter(
                stop_time__lte=self._parse_datetime(options["end"], "end")
            )
        queryset = queryset.order_by("stop_time", "unique_id").only(
            "unique_id",
            "username",
            "organization_id",
            "input_octets",
            "output_octets",
            "calling_station_id",
            "called_station_id",
            "stop_time",
            "terminate_cause",
        )
        count = queryset.count()
        if not options["commit"]:
            self.stdout.write(f"Dry run: {count} closed sessions would be processed.")
            return
        processed = 0
        chunk_size = options["chunk_size"]
        self.stdout.write(f"Starting to rebuild {count} accounting metrics.")
        for session in queryset.iterator(chunk_size=chunk_size):
            self._delete_radius_accounting_metric(session)
            tasks.post_save_radiusaccounting(
                username=session.username,
                organization_id=str(session.organization_id),
                input_octets=session.input_octets,
                output_octets=session.output_octets,
                calling_station_id=session.calling_station_id,
                called_station_id=session.called_station_id,
                time=session.stop_time,
            )
            processed += 1
            if processed % chunk_size == 0 or processed == count:
                self.stdout.write(
                    f"Processed {processed} of {count} accounting metrics."
                )

    def _parse_datetime(self, value, option):
        parsed = parse_datetime(value)
        if parsed is None:
            raise CommandError(f"Invalid --{option} datetime: {value}")
        if timezone.is_naive(parsed):
            parsed = timezone.make_aware(parsed)
        return parsed

    def _delete_radius_accounting_metric(self, session):
        calling_station_ids = self._get_station_id_formats(session.calling_station_id)
        tags = {
            "organization_id": [session.organization_id],
            "calling_station_id": map(sha1_hash, calling_station_ids),
            "called_station_id": self._get_station_id_formats(
                session.called_station_id
            ),
        }
        where = " AND ".join(
            "({})".format(
                " OR ".join(
                    f"\"{key}\" = '{self._escape_tag_value(value)}'" for value in values
                )
            )
            for key, values in tags.items()
        )
        timeseries_db.query(
            "DELETE FROM radius_acc "
            f"WHERE time = '{session.stop_time.isoformat()}' AND {where}"
        )

    def _get_station_id_formats(self, station_id):
        """
        Returns the values a point may have been tagged with, which can
        predate the normalization of MAC addresses.
        """
        if not station_id or not MAC_ADDRESS_PATTERN.fullmatch(station_id):
            return [station_id]
        mac = sanitize_mac_address(station_id)
        dotted = "{}{}.{}{}.{}{}".format(*mac.split(":"))
        formats = (mac, mac.replace(":", "-"), dotted)
        # shortcut: mixed case values are not matched, add them
        # if a NAS is found which sends them
        return {station_id, *formats, *(value.lower() for value in formats)}

    def _escape_tag_value(self, value):
        return str(value).replace("'", r"\'")
