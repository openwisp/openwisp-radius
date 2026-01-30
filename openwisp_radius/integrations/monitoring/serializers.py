from django.utils import formats, timezone
from rest_framework import serializers
from swapper import load_model

RadiusAccounting = load_model("openwisp_radius", "RadiusAccounting")


class MonitoringRadiusAccountingSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for RADIUS accounting in monitoring integration
    that formats datetime fields server-side using Django's localization
    for consistency with Django admin datetime formatting.
    """

    start_time = serializers.SerializerMethodField()
    stop_time = serializers.SerializerMethodField()

    def _format_datetime(self, dt):
        """
        Format a datetime using Django's localization settings.
        Handles both naive and timezone-aware datetimes.
        """
        if dt is None:
            return None
        if timezone.is_aware(dt):
            dt = timezone.localtime(dt)
        return formats.date_format(dt, "DATETIME_FORMAT")

    def get_start_time(self, obj):
        """Format start_time using Django's localization settings"""
        return self._format_datetime(obj.start_time)

    def get_stop_time(self, obj):
        """Format stop_time using Django's localization settings"""
        return self._format_datetime(obj.stop_time)

    class Meta:
        model = RadiusAccounting
        fields = [
            "session_id",
            "unique_id",
            "username",
            "input_octets",
            "output_octets",
            "calling_station_id",
            "called_station_id",
            "start_time",
            "stop_time",
        ]
        read_only_fields = fields
