import os
import sys

from celery.schedules import crontab

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TESTING = sys.argv[1] == 'test'
SHELL = 'shell' in sys.argv or 'shell_plus' in sys.argv

# Set DEBUG to False in production
DEBUG = True
INTERNAL_IPS = ['127.0.0.1']
SECRET_KEY = '&a@f(0@lrl%606smticbu20=pvribdvubk5=gjti8&n1y%bi&4'

ALLOWED_HOSTS = []
OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS = ['127.0.0.1']
OPENWISP_RADIUS_COA_ENABLED = True
OPENWISP_RADIUS_ALLOWED_MOBILE_PREFIXES = ['+44', '+39', '+237', '+595']

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'django.contrib.gis',
    # all-auth
    'django.contrib.sites',
    # overrides allauth templates
    # must precede allauth
    'openwisp_users.accounts',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'django_extensions',
    # openwisp2 modules
    'openwisp_users',
    'openwisp_controller.pki',
    'openwisp_controller.config',
    'openwisp_controller.geo',
    'openwisp_controller.connection',
    'openwisp_ipam',
    'openwisp_monitoring.monitoring',
    'openwisp_monitoring.device',
    'openwisp_monitoring.check',
    'nested_admin',
    'openwisp_notifications',
    'flat_json_widget',
    'dj_rest_auth',
    'dj_rest_auth.registration',
    'openwisp_radius',
    'openwisp_radius.integrations.monitoring',
    # openwisp2 admin theme
    # (must be loaded here)
    'openwisp_utils.admin_theme',
    'admin_auto_filters',
    # admin
    'django.contrib.admin',
    'django.forms',
    # other dependencies
    'sortedm2m',
    'reversion',
    'leaflet',
    'rest_framework',
    'rest_framework_gis',
    'rest_framework.authtoken',
    'django_filters',
    'private_storage',
    'drf_yasg',
    'import_export',
    'channels',
    # 'debug_toolbar',
]

LOGIN_REDIRECT_URL = 'admin:index'

AUTHENTICATION_BACKENDS = (
    'openwisp_users.backends.UsersAuthenticationBackend',
    'openwisp_radius.saml.backends.OpenwispRadiusSaml2Backend',
    'sesame.backends.ModelBackend',
)

AUTH_USER_MODEL = 'openwisp_users.User'
SITE_ID = 1

STATICFILES_FINDERS = [
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    'openwisp_utils.staticfiles.DependencyFinder',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'sesame.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'djangosaml2.middleware.SamlSessionMiddleware',
    # 'debug_toolbar.middleware.DebugToolbarMiddleware',
]

SESSION_COOKIE_SECURE = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SAML_ALLOWED_HOSTS = []
SAML_USE_NAME_ID_AS_USERNAME = True
SAML_CREATE_UNKNOWN_USER = True
SAML_CONFIG = {}

ROOT_URLCONF = 'openwisp2.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'OPTIONS': {
            'loaders': [
                'django.template.loaders.filesystem.Loader',
                'django.template.loaders.app_directories.Loader',
                'openwisp_utils.loaders.DependencyLoader',
            ],
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'openwisp_utils.admin_theme.context_processor.menu_groups',
                'openwisp_notifications.context_processors.notification_api_settings',
            ],
        },
    }
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'openwisp_radius.db'),
    }
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': TESTING,
    'filters': {'require_debug_true': {'()': 'django.utils.log.RequireDebugTrue'}},
    'formatters': {
        'django.server': {
            '()': 'django.utils.log.ServerFormatter',
            'format': '[{server_time}] {message}',
            'style': '{',
        }
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'filters': ['require_debug_true'],
            'class': 'logging.StreamHandler',
        },
    },
}

if not TESTING:
    LOGGING['handlers'].update(
        {
            'django.server': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'django.server',
            },
        }
    )
    LOGGING['loggers'] = {
        'django': {'handlers': ['console'], 'level': 'INFO'},
        'django.server': {
            'handlers': ['django.server'],
            'level': 'INFO',
            'propagate': False,
        },
        'openwisp_radius': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    }

if not TESTING and SHELL:
    LOGGING['loggers'] = {
        'django.db': {
            'level': 'DEBUG',
            'handlers': ['console'],
            'propagate': False,
        },
        '': {
            # this sets root level logger to log debug and higher level
            # logs to console. All other loggers inherit settings from
            # root level logger.
            'handlers': ['console', 'django.server'],
            'level': 'DEBUG',
            'propagate': False,
        },
    }

# WARNING: for development only!
AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = 'en-gb'
TIME_ZONE = 'America/Asuncion'  # used to replicate timezone related bug, do not change!
USE_I18N = True
USE_L10N = True
USE_TZ = True
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
PRIVATE_STORAGE_ROOT = os.path.join(MEDIA_ROOT, 'private')
EMAIL_PORT = '1025'
MEDIA_URL = '/media/'
STATIC_URL = '/static/'

# for development only
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

SOCIALACCOUNT_PROVIDERS = {
    'facebook': {
        'METHOD': 'oauth2',
        'SCOPE': ['email', 'public_profile'],
        'AUTH_PARAMS': {'auth_type': 'reauthenticate'},
        'INIT_PARAMS': {'cookie': True},
        'FIELDS': ['id', 'email', 'name', 'first_name', 'last_name', 'verified'],
        'VERIFIED_EMAIL': True,
    },
    'google': {'SCOPE': ['profile', 'email'], 'AUTH_PARAMS': {'access_type': 'online'}},
}

redis_host = os.getenv('REDIS_HOST', 'localhost')

OPENWISP_RADIUS_PASSWORD_RESET_URLS = {
    '__all__': (
        'http://localhost:8080/{organization}/password/reset/confirm/{uid}/{token}'
    ),
}

if TESTING:
    CELERY_BROKER_URL = os.getenv('REDIS_URL', f'redis://{redis_host}/1')
else:
    OPENWISP_RADIUS_GROUPCHECK_ADMIN = True
    OPENWISP_RADIUS_GROUPREPLY_ADMIN = True
    OPENWISP_RADIUS_USERGROUP_ADMIN = True
    OPENWISP_RADIUS_USER_ADMIN_RADIUSTOKEN_INLINE = True
    CELERY_TASK_ALWAYS_EAGER = True
    CELERY_TASK_EAGER_PROPAGATES = True
    CELERY_BROKER_URL = 'memory://'

TEST_RUNNER = 'openwisp_utils.tests.TimeLoggingTestRunner'

CELERY_BEAT_SCHEDULE = {
    'deactivate_expired_users': {
        'task': 'openwisp_radius.tasks.cleanup_stale_radacct',
        'schedule': crontab(hour=0, minute=0),
        'args': None,
        'relative': True,
    },
    'delete_old_radiusbatch_users': {
        'task': 'openwisp_radius.tasks.delete_old_radiusbatch_users',
        'schedule': crontab(hour=0, minute=10),
        'args': [365],
        'relative': True,
    },
    'cleanup_stale_radacct': {
        'task': 'openwisp_radius.tasks.cleanup_stale_radacct',
        'schedule': crontab(hour=0, minute=20),
        'args': [365],
        'relative': True,
    },
    'delete_old_postauth': {
        'task': 'openwisp_radius.tasks.delete_old_postauth',
        'schedule': crontab(hour=0, minute=30),
        'args': [365],
        'relative': True,
    },
    'delete_old_radacct': {
        'task': 'openwisp_radius.tasks.delete_old_radacct',
        'schedule': crontab(hour=0, minute=40),
        'args': [365],
        'relative': True,
    },
    'unverify_inactive_users': {
        'task': 'openwisp_radius.tasks.unverify_inactive_users',
        'schedule': crontab(hour=1, minute=30),
        'relative': True,
    },
    'delete_inactive_users': {
        'task': 'openwisp_radius.tasks.delete_inactive_users',
        'schedule': crontab(hour=1, minute=50),
        'relative': True,
    },
}

SENDSMS_BACKEND = 'sendsms.backends.console.SmsBackend'
OPENWISP_RADIUS_EXTRA_NAS_TYPES = (('cisco', 'Cisco Router'),)

REST_AUTH = {
    'SESSION_LOGIN': False,
    'PASSWORD_RESET_SERIALIZER': 'openwisp_radius.api.serializers.PasswordResetSerializer',
    'REGISTER_SERIALIZER': 'openwisp_radius.api.serializers.RegisterSerializer',
}

ACCOUNT_EMAIL_CONFIRMATION_ANONYMOUS_REDIRECT_URL = 'email_confirmation_success'
ACCOUNT_EMAIL_CONFIRMATION_AUTHENTICATED_REDIRECT_URL = 'email_confirmation_success'

# OPENWISP_RADIUS_PASSWORD_RESET_URLS = {
#     # use the uuid because the slug can change
#     # 'dabbd57a-11ca-4277-8dbb-ad21057b5ecd': 'https://org.com/{organization}/password/reset/confirm/{uid}/{token}',
#     # fallback in case the specific org page is not defined
#     '__all__': 'https://example.com/{{organization}/password/reset/confirm/{uid}/{token}',
# }

if TESTING:
    OPENWISP_RADIUS_SMS_TOKEN_MAX_USER_DAILY = 3
    OPENWISP_RADIUS_SMS_TOKEN_MAX_ATTEMPTS = 3
    OPENWISP_RADIUS_SMS_TOKEN_MAX_IP_DAILY = 4
    SENDSMS_BACKEND = 'sendsms.backends.dummy.SmsBackend'
else:
    OPENWISP_RADIUS_SMS_TOKEN_MAX_USER_DAILY = 10

OPENWISP_USERS_AUTH_API = True

TIMESERIES_DATABASE = {
    'BACKEND': 'openwisp_monitoring.db.backends.influxdb',
    'USER': 'openwisp',
    'PASSWORD': 'openwisp',
    'NAME': 'openwisp2',
    'HOST': os.getenv('INFLUXDB_HOST', 'localhost'),
    'PORT': '8086',
    # UDP writes are disabled by default
    'OPTIONS': {'udp_writes': False, 'udp_port': 8089},
}
EXTENDED_APPS = ['django_x509', 'django_loci']

ASGI_APPLICATION = 'openwisp2.routing.application'
if TESTING:
    CHANNEL_LAYERS = {'default': {'BACKEND': 'channels.layers.InMemoryChannelLayer'}}
else:
    CHANNEL_LAYERS = {
        'default': {
            'BACKEND': 'channels_redis.core.RedisChannelLayer',
            'CONFIG': {'hosts': [f'redis://{redis_host}/7']},
        }
    }


if os.environ.get('SAMPLE_APP', False):
    INSTALLED_APPS.remove('openwisp_radius')
    INSTALLED_APPS.remove('openwisp_users')
    INSTALLED_APPS.append('openwisp2.sample_radius')
    INSTALLED_APPS.append('openwisp2.sample_users')
    # EXTENDED_APPS = ('openwisp_radius', 'openwisp_users')
    AUTH_USER_MODEL = 'sample_users.User'
    OPENWISP_USERS_GROUP_MODEL = 'sample_users.Group'
    OPENWISP_USERS_ORGANIZATION_MODEL = 'sample_users.Organization'
    OPENWISP_USERS_ORGANIZATIONUSER_MODEL = 'sample_users.OrganizationUser'
    OPENWISP_USERS_ORGANIZATIONOWNER_MODEL = 'sample_users.OrganizationOwner'
    OPENWISP_USERS_ORGANIZATIONINVITATION_MODEL = 'sample_users.OrganizationInvitation'
    OPENWISP_RADIUS_RADIUSREPLY_MODEL = 'sample_radius.RadiusReply'
    OPENWISP_RADIUS_RADIUSGROUPREPLY_MODEL = 'sample_radius.RadiusGroupReply'
    OPENWISP_RADIUS_RADIUSCHECK_MODEL = 'sample_radius.RadiusCheck'
    OPENWISP_RADIUS_RADIUSGROUPCHECK_MODEL = 'sample_radius.RadiusGroupCheck'
    OPENWISP_RADIUS_RADIUSACCOUNTING_MODEL = 'sample_radius.RadiusAccounting'
    OPENWISP_RADIUS_NAS_MODEL = 'sample_radius.Nas'
    OPENWISP_RADIUS_RADIUSUSERGROUP_MODEL = 'sample_radius.RadiusUserGroup'
    OPENWISP_RADIUS_REGISTEREDUSER_MODEL = 'sample_radius.RadiusUserGroup'
    OPENWISP_RADIUS_RADIUSPOSTAUTH_MODEL = 'sample_radius.RadiusPostAuth'
    OPENWISP_RADIUS_RADIUSBATCH_MODEL = 'sample_radius.RadiusBatch'
    OPENWISP_RADIUS_RADIUSGROUP_MODEL = 'sample_radius.RadiusGroup'
    OPENWISP_RADIUS_RADIUSTOKEN_MODEL = 'sample_radius.RadiusToken'
    OPENWISP_RADIUS_PHONETOKEN_MODEL = 'sample_radius.PhoneToken'
    OPENWISP_RADIUS_REGISTEREDUSER_MODEL = 'sample_radius.RegisteredUser'
    OPENWISP_RADIUS_ORGANIZATIONRADIUSSETTINGS_MODEL = (
        'sample_radius.OrganizationRadiusSettings'
    )
    # Rename sample_app database
    DATABASES['default']['NAME'] = os.path.join(BASE_DIR, 'sample_radius.db')
    CELERY_IMPORTS = ('openwisp_radius.tasks',)

if os.environ.get('SAMPLE_APP', False) and TESTING:
    # Required for openwisp-users tests
    OPENWISP_ORGANIZATION_USER_ADMIN = True
    OPENWISP_ORGANIZATION_OWNER_ADMIN = True
    OPENWISP_USERS_AUTH_API = True

# CORS headers, useful during development and testing
try:
    import corsheaders  # noqa

    INSTALLED_APPS.append('corsheaders')
    MIDDLEWARE.insert(
        MIDDLEWARE.index('django.middleware.common.CommonMiddleware'),
        'corsheaders.middleware.CorsMiddleware',
    )
    # WARNING: for development only!
    CORS_ORIGIN_ALLOW_ALL = True
except ImportError:
    pass

# local settings must be imported before test runner otherwise they'll be ignored
try:
    from .local_settings import *
except ImportError:
    pass

FORM_RENDERER = 'django.forms.renderers.TemplatesSetting'

if not TESTING:
    CACHES = {
        'default': {
            'BACKEND': 'django_redis.cache.RedisCache',
            'LOCATION': 'redis://127.0.0.1:6379/6',
            'OPTIONS': {
                'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            },
        }
    }
