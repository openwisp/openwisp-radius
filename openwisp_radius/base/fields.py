from django.db import models

from ..utils import sanitize_mac_address


class MacAddressField(models.CharField):
    """Saves MAC addresses as AA:BB:CC:DD:EE:FF, whatever format was sent."""

    # Django also calls this for filter values, so filters accept any format.
    def to_python(self, value):
        return sanitize_mac_address(super().to_python(value))

    def pre_save(self, model_instance, add):
        value = sanitize_mac_address(super().pre_save(model_instance, add))
        setattr(model_instance, self.attname, value)
        return value
