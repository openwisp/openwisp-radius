from django.dispatch import Signal

radius_accounting_success = Signal()  # providing_args=['accounting_data', 'view']
radius_accounting_closed = Signal()  # providing_args=['instance']
