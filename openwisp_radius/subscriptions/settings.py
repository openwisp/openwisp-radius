from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

PAYMENT_SUCCESS_URL = getattr(settings, 'PAYMENT_SUCCESS_URL', 'http://example.com/success/')
PAYMENT_FAILURE_URL = getattr(settings, 'PAYMENT_FAILURE_URL', 'http://example.com/failure/')
PAYMENT_ADMIN_EDITABLE = getattr(settings, 'PAYMENT_ADMIN_EDITABLE', False)
PAYMENT_VARIANTS = getattr(settings, 'PAYMENT_VARIANTS', {
    'default': ('payments.dummy.DummyProvider', {}),
})
PAYMENT_VARIANT_CHOICES = [(key, key) for key in PAYMENT_VARIANTS.keys()]

try:
    PAYMENT_VARIANTS['default']
except KeyError:
    raise ImproperlyConfigured('a default payment variant must always be present')

try:
    TAX = getattr(settings, 'PLANS_TAX')
except AttributeError:
    raise ImproperlyConfigured('settings.PLANS_TAX must be specified')

try:
    CURRENCY = getattr(settings, 'PLANS_CURRENCY')
except AttributeError:
    raise ImproperlyConfigured('settings.PLANS_CURRENCY must be specified')

TEMP_GROUP_CHECKS = getattr(settings, 'SUBSCRIPTIONS_TEMPORARY_GROUP_CHECKS', [
    {
        'attribute': 'Max-Daily-Session',
        'op': ':=',
        'value': '1200'  # 20 minutes
    },
    {
        'attribute': 'Max-Daily-Session-Traffic',
        'op': ':=',
        'value': '100000000'  # 100 MB
    },
    {
        'attribute': 'Max-All-Session-Time',
        'op': ':=',
        'value': '2400'  # 40 minutes
    }
])
TEMP_GROUP_REPLIES = getattr(settings, 'SUBSCRIPTIONS_TEMPORARY_GROUP_CHECKS', [
    {
        'attribute': 'Reply-Message',
        'op': ':=',
        'value': 'You have 10 minutes to complete '
                 'your payment before the session expires.'
    },
    {
        'attribute': 'Session-Timeout',
        'op': ':=',
        'value': '600'  # 10 minutes
    }
])
