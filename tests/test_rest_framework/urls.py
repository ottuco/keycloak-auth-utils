from django.urls import include, path

urlpatterns = [
    path("", include("tests.test_rest_framework.polls.urls")),
]
