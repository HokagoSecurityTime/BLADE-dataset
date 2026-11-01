SECRET_KEY="local-synthetic-fixture"
DEBUG=False
ALLOWED_HOSTS=["*"]
ROOT_URLCONF="urls"
INSTALLED_APPS=["django.contrib.auth","django.contrib.contenttypes","rest_framework","drf_spectacular"]
DATABASES={"default":{"ENGINE":"django.db.backends.sqlite3","NAME":":memory:"}}
REST_FRAMEWORK={"DEFAULT_SCHEMA_CLASS":"drf_spectacular.openapi.AutoSchema","DEFAULT_AUTHENTICATION_CLASSES":[],"UNAUTHENTICATED_USER":None}
