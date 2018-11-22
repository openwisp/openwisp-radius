from settings import *  # noqa

from decimal import Decimal


INSTALLED_APPS += [
    'payments',
    'ordered_model',
    'plans',
    'openwisp_radius.subscriptions'
]

PAYMENT_HOST = '10.40.0.54:8000'
PAYMENT_USES_SSL = False
PAYMENT_MODEL = 'subscriptions.Payment'
PAYMENT_VARIANTS = {
    'dummy': ('payments.dummy.DummyProvider', {}),
    'default': ('payments.paypal.PaypalProvider', {
        'client_id': 'ASWGFeaCOCrZkGWU1Ow7r16OqLy3m1yxPhMkv3ocz_LDn1N4dzqxKK6abgJ4fRKxbQv1ealdkUIK1stR',
        'secret': 'ED_cPh9F7L9XqSJO1ALN1WHpHWxNA9JykM0DLCu22Y_vc-EpK59bv4PKCxuTNO70UhHqGVXP4jMjfjHg',
        'endpoint': 'https://api.sandbox.paypal.com',
        'capture': True
    })
}
PAYMENT_SUCCESS_URL = 'http://10.40.0.54/oxynet-captivepage/success.html'
PAYMENT_FAILURE_URL = 'http://10.40.0.54/oxynet-captivepage/failure.html'
PAYMENT_ADMIN_EDITABLE = True

PLANS_INVOICE_COUNTER_RESET = 3
PLANS_INVOICE_ISSUER = {
    'issuer_name': 'Joe Doe Company',
    'issuer_street': 'Django street, 34',
    'issuer_zipcode': '123-3444',
    'issuer_city': 'SolarCity',
    'issuer_country': 'EE',
    'issuer_tax_number': '1222233334444555',
}

PLANS_TAX = Decimal('22.0')
PLANS_CURRENCY = 'EUR'

REST_AUTH_REGISTER_SERIALIZERS = {
    'REGISTER_SERIALIZER': 'openwisp_radius.subscriptions.serializers.RegisterSerializer',
}
REST_AUTH_SERIALIZERS = {
    'TOKEN_SERIALIZER': 'openwisp_radius.subscriptions.serializers.TokenSerializer',
}

# local settings must be imported before test runner otherwise they'll be ignored
try:
    from local_settings import *  # noqa
except ImportError:
    pass
