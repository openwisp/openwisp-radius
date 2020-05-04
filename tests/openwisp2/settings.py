import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TESTING = sys.argv[1] == 'test'

# Set DEBUG to False in production
DEBUG = True

SECRET_KEY = '&a@f(0@lrl%606smticbu20=pvribdvubk5=gjti8&n1y%bi&4'

ALLOWED_HOSTS = []

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
    'django_extensions',
]

LOGIN_REDIRECT_URL = 'admin:index'

AUTH_USER_MODEL = 'openwisp_users.User'
SITE_ID = '1'

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

if TESTING:
    OPENWISP_RADIUS_GROUPCHECK_ADMIN = True
    OPENWISP_RADIUS_GROUPREPLY_ADMIN = True
    OPENWISP_RADIUS_USERGROUP_ADMIN = True

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
    INSTALLED_APPS.remove('openwisp_radius',)
    EXTENDED_APPS = ['openwisp_radius']
    INSTALLED_APPS.append('openwisp2.sample_radius')
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
