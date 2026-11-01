from api import urlpatterns
from django.urls import path
from drf_spectacular.views import SpectacularAPIView
urlpatterns += [path("openapi.json", SpectacularAPIView.as_view())]
