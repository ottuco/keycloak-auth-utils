from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import UserTestAPI

router = DefaultRouter()
urlpatterns = [
    path("user/", UserTestAPI.as_view()),
] + router.urls
