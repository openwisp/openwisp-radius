from django.dispatch import Signal

radius_accounting_success = Signal(providing_args=['account_data'])
