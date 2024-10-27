from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'rest_framework',
    'feedback_form'
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth'
            ],
        },
    },
]

USE_TZ = False

STATIC_URL = '/static/'

ROOT_URLCONF = 'feedback_form.urls'

RECAPTCHA_PUBLIC_KEY = 'recaptcha-public-key'
RECAPTCHA_SECRET_KEY = 'recaptcha-secret-key'

FEEDBACK_EMAIL_INBOX = 'for@example.com'

SECRET_KEY = 'test-secret-key'
DEBUG = True
