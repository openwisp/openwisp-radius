import os
import sys

from celery.schedules import crontab

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TESTING = sys.argv[1] == 'test'

# Set DEBUG to False in production
DEBUG = True

SECRET_KEY = '&a@f(0@lrl%606smticbu20=pvribdvubk5=gjti8&n1y%bi&4'

ALLOWED_HOSTS = []
OPENWISP_RADIUS_FREERADIUS_ALLOWED_HOSTS = ['127.0.0.1']

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # openwisp admin theme
    'openwisp_utils.admin_theme',
    # all-auth
    'django.contrib.sites',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    # admin
    'django.contrib.admin',
    # rest framework
    'rest_framework',
    'django_filters',
    # registration
    'rest_framework.authtoken',
    'rest_auth',
    'rest_auth.registration',
    # social login
    'allauth.socialaccount.providers.facebook',
    'allauth.socialaccount.providers.google',
    # openwisp radius
    'openwisp_radius',
    'openwisp_users',
    'private_storage',
    'drf_yasg',
    'django_extensions',
]

LOGIN_REDIRECT_URL = 'admin:index'

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
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

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
                'openwisp_utils.admin_theme.context_processor.menu_items',
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

# WARNING: for development only!
AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = 'en-gb'
TIME_ZONE = 'America/Asuncion'  # used to replicate timezone related bug, do not change!
USE_I18N = False
USE_L10N = False
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

if not TESTING:
    CELERY_BROKER_URL = os.getenv('REDIS_URL', f'redis://{redis_host}/1')
else:
    OPENWISP_RADIUS_GROUPCHECK_ADMIN = True
    OPENWISP_RADIUS_GROUPREPLY_ADMIN = True
    OPENWISP_RADIUS_USERGROUP_ADMIN = True
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
    'delete_old_users': {
        'task': 'openwisp_radius.tasks.delete_old_users',
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
}

SENDSMS_BACKEND = 'sendsms.backends.console.SmsBackend'
OPENWISP_RADIUS_EXTRA_NAS_TYPES = (('cisco', 'Cisco Router'),)

REST_AUTH_SERIALIZERS = {
    'PASSWORD_RESET_SERIALIZER': 'openwisp_radius.api.serializers.PasswordResetSerializer'
}

REST_AUTH_REGISTER_SERIALIZERS = {
    'REGISTER_SERIALIZER': 'openwisp_radius.api.serializers.RegisterSerializer'
}

# OPENWISP_RADIUS_PASSWORD_RESET_URLS = {
#     # fallback in case the specific org page is not defined
#     'default': 'https://example.com/{organization}/password/reset/{uid}/{token}',
#     # use the uuid because the slug can change
#     # 'dabbd57a-11ca-4277-8dbb-ad21057b5ecd': 'https://organization.com/{organization}/password/reset/{uid}/{token}',
# }

OPENWISP_RADIUS_SMS_TOKEN_MAX_IP_DAILY = 4

if os.environ.get('SAMPLE_APP', False):
    INSTALLED_APPS.remove('openwisp_radius')
    INSTALLED_APPS.remove('openwisp_users')
    INSTALLED_APPS.append('openwisp2.sample_radius')
    INSTALLED_APPS.append('openwisp2.sample_users')
    EXTENDED_APPS = ('openwisp_radius', 'openwisp_users')
    AUTH_USER_MODEL = 'sample_users.User'
    OPENWISP_USERS_GROUP_MODEL = 'sample_users.Group'
    OPENWISP_USERS_ORGANIZATION_MODEL = 'sample_users.Organization'
    OPENWISP_USERS_ORGANIZATIONUSER_MODEL = 'sample_users.OrganizationUser'
    OPENWISP_USERS_ORGANIZATIONOWNER_MODEL = 'sample_users.OrganizationOwner'
    OPENWISP_RADIUS_RADIUSREPLY_MODEL = 'sample_radius.RadiusReply'
    OPENWISP_RADIUS_RADIUSGROUPREPLY_MODEL = 'sample_radius.RadiusGroupReply'
    OPENWISP_RADIUS_RADIUSCHECK_MODEL = 'sample_radius.RadiusCheck'
    OPENWISP_RADIUS_RADIUSGROUPCHECK_MODEL = 'sample_radius.RadiusGroupCheck'
    OPENWISP_RADIUS_RADIUSACCOUNTING_MODEL = 'sample_radius.RadiusAccounting'
    OPENWISP_RADIUS_NAS_MODEL = 'sample_radius.Nas'
    OPENWISP_RADIUS_RADIUSUSERGROUP_MODEL = 'sample_radius.RadiusUserGroup'
    OPENWISP_RADIUS_RADIUSPOSTAUTH_MODEL = 'sample_radius.RadiusPostAuth'
    OPENWISP_RADIUS_RADIUSBATCH_MODEL = 'sample_radius.RadiusBatch'
    OPENWISP_RADIUS_RADIUSGROUP_MODEL = 'sample_radius.RadiusGroup'
    OPENWISP_RADIUS_RADIUSTOKEN_MODEL = 'sample_radius.RadiusToken'
    OPENWISP_RADIUS_PHONETOKEN_MODEL = 'sample_radius.PhoneToken'
    OPENWISP_RADIUS_ORGANIZATIONRADIUSSETTINGS_MODEL = (
        'sample_radius.OrganizationRadiusSettings'
    )
    # Rename sample_app database
    DATABASES['default']['NAME'] = os.path.join(BASE_DIR, 'sample_radius.db')
    CELERY_IMPORTS = ('openwisp_radius.tasks',)

if os.environ.get('SAMPLE_APP', False) and TESTING:
    # Required for openwisp-users tests
    OPENWISP_ORGANIZATON_USER_ADMIN = True
    OPENWISP_ORGANIZATON_OWNER_ADMIN = True
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
    from local_settings import *
except ImportError:
    pass
