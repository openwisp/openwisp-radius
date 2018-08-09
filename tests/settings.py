import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Set DEBUG to False in production
DEBUG = True

SECRET_KEY = '&a@f(0@lrl%606smticbu20=pvribdvubk5=gjti8&n1y%bi&4'

DJANGO_FREERADIUS_API_TOKEN = "gsoc2018djfapitoken"

ALLOWED_HOSTS = []

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'openwisp_utils.admin_theme',
    # all-auth
    'django.contrib.sites',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    # openwisp2 modules
    'openwisp_users',
    'openwisp_radius',
    # admin
    'django.contrib.admin',
    # rest framework
    'rest_framework',
    'django_filters'
]

EXTENDED_APPS = ['django_freeradius']

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

ROOT_URLCONF = 'urls'

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
            ],
        },
    },
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'freeradius.db'),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-gb'
TIME_ZONE = 'Europe/Rome'
USE_I18N = False
USE_L10N = False
USE_TZ = True
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
EMAIL_PORT = '1025'
MEDIA_URL = '/media/'
STATIC_URL = '/static/'

# for development only
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Swapper model definitions
DJANGO_FREERADIUS_RADIUSREPLY_MODEL = "openwisp_radius.RadiusReply"
DJANGO_FREERADIUS_RADIUSGROUPREPLY_MODEL = "openwisp_radius.RadiusGroupReply"
DJANGO_FREERADIUS_RADIUSCHECK_MODEL = "openwisp_radius.RadiusCheck"
DJANGO_FREERADIUS_RADIUSGROUPCHECK_MODEL = "openwisp_radius.RadiusGroupCheck"
DJANGO_FREERADIUS_RADIUSACCOUNTING_MODEL = "openwisp_radius.RadiusAccounting"
DJANGO_FREERADIUS_NAS_MODEL = "openwisp_radius.Nas"
DJANGO_FREERADIUS_RADIUSUSERGROUP_MODEL = "openwisp_radius.RadiusUserGroup"
DJANGO_FREERADIUS_RADIUSPOSTAUTH_MODEL = "openwisp_radius.RadiusPostAuth"
DJANGO_FREERADIUS_RADIUSBATCH_MODEL = "openwisp_radius.RadiusBatch"
DJANGO_FREERADIUS_RADIUSPROFILE_MODEL = "openwisp_radius.RadiusProfile"
DJANGO_FREERADIUS_RADIUSUSERPROFILE_MODEL = "openwisp_radius.RadiusUserProfile"
