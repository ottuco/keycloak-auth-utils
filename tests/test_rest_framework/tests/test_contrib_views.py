"""Tests for keycloak_utils.contrib.django.views."""

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import RequestFactory
from rest_framework.test import APIRequestFactory, force_authenticate

from keycloak_utils.contrib.django.views import (
    AllPermissionsView,
    ErrorView,
    RolePermissionsView,
)

pytestmark = pytest.mark.django_db

User = get_user_model()


class TestErrorView:
    """Tests for ErrorView XSS vulnerability protection."""

    @pytest.mark.parametrize(
        "malicious_input,expected_output",
        [
            pytest.param(
                "<script>alert('XSS')</script>",
                "<html><body><h1>Error</h1><p>&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;</p></body></html>",
                id="script-tag-injection",
            ),
            pytest.param(
                '<img src=x onerror="alert(1)">',
                "<html><body><h1>Error</h1><p>&lt;img src=x onerror=&quot;alert(1)&quot;&gt;</p></body></html>",
                id="img-onerror-event",
            ),
            pytest.param(
                '<a href="javascript:alert(1)">Click</a>',
                "<html><body><h1>Error</h1><p>&lt;a href=&quot;javascript:alert(1)&quot;&gt;Click&lt;/a&gt;</p></body></html>",
                id="javascript-protocol",
            ),
            pytest.param(
                "<svg/onload=alert(document.domain)>",
                "<html><body><h1>Error</h1><p>&lt;svg/onload=alert(document.domain)&gt;</p></body></html>",
                id="svg-onload-event",
            ),
            pytest.param(
                '<div onload="alert(1)" onclick="alert(2)">test</div>',
                "<html><body><h1>Error</h1><p>&lt;div onload=&quot;alert(1)&quot; onclick=&quot;alert(2)&quot;&gt;test&lt;/div&gt;</p></body></html>",
                id="multiple-event-handlers",
            ),
            pytest.param(
                '"><script>alert("XSS")</script><"',
                "<html><body><h1>Error</h1><p>&quot;&gt;&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;&lt;&quot;</p></body></html>",
                id="html-entity-breaking",
            ),
            pytest.param(
                "<script>alert(1)</script><img src=x onerror=alert(2)><svg/onload=alert(3)>",
                "<html><body><h1>Error</h1><p>&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(2)&gt;&lt;svg/onload=alert(3)&gt;</p></body></html>",
                id="multiple-xss-vectors",
            ),
        ],
    )
    def test_escapes_xss_attacks(self, malicious_input, expected_output):
        """Test that various XSS attack vectors are properly escaped."""
        factory = RequestFactory()
        request = factory.get("/error/", {"error": malicious_input})

        view = ErrorView.as_view()
        response = view(request)

        assert response.status_code == 200
        assert response.content.decode() == expected_output

    def test_default_message_when_no_parameter(self):
        """Test that default error message is shown when no error parameter."""
        factory = RequestFactory()
        request = factory.get("/error/")

        view = ErrorView.as_view()
        response = view(request)

        assert response.status_code == 200
        assert (
            response.content.decode()
            == "<html><body><h1>Error</h1><p>An unknown error occurred</p></body></html>"
        )

    def test_default_message_when_empty_parameter(self):
        """Test that default error message is shown for empty parameter."""
        factory = RequestFactory()
        request = factory.get("/error/", {"error": ""})

        view = ErrorView.as_view()
        response = view(request)

        assert response.status_code == 200
        assert (
            response.content.decode()
            == "<html><body><h1>Error</h1><p>An unknown error occurred</p></body></html>"
        )

    def test_safe_error_message_displayed_correctly(self):
        """Test that safe, normal error messages are displayed correctly."""
        factory = RequestFactory()
        safe_message = "Authentication failed. Please try again."
        request = factory.get("/error/", {"error": safe_message})

        view = ErrorView.as_view()
        response = view(request)

        assert response.status_code == 200
        assert (
            response.content.decode()
            == "<html><body><h1>Error</h1><p>Authentication failed. Please try again.</p></body></html>"
        )


@pytest.fixture()
def api_factory():
    return APIRequestFactory()


@pytest.fixture()
def admin_user():
    return User.objects.create_user(
        username="admin", password="pass", is_staff=True, is_superuser=True,
    )


@pytest.fixture()
def regular_user():
    return User.objects.create_user(username="regular", password="pass")


@pytest.fixture()
def sample_permission():
    ct = ContentType.objects.get_for_model(User)
    perm, _ = Permission.objects.get_or_create(
        codename="test_perm",
        content_type=ct,
        defaults={"name": "Test Permission"},
    )
    return perm


class TestAllPermissionsView:
    """Tests for AllPermissionsView."""

    def test_unauthenticated_returns_403(self, api_factory):
        request = api_factory.get("/permissions/")
        response = AllPermissionsView.as_view()(request)
        assert response.status_code == 403

    def test_non_admin_returns_403(self, api_factory, regular_user):
        request = api_factory.get("/permissions/")
        force_authenticate(request, user=regular_user)
        response = AllPermissionsView.as_view()(request)
        assert response.status_code == 403

    def test_admin_returns_200(self, api_factory, admin_user):
        request = api_factory.get("/permissions/")
        force_authenticate(request, user=admin_user)
        response = AllPermissionsView.as_view()(request)
        assert response.status_code == 200

    def test_admin_returns_all_permissions(self, api_factory, admin_user):
        request = api_factory.get("/permissions/")
        force_authenticate(request, user=admin_user)
        response = AllPermissionsView.as_view()(request)
        response.render()
        expected_count = Permission.objects.count()
        assert len(response.data) == expected_count

    def test_permissions_serialized_as_app_label_dot_codename(
        self, api_factory, admin_user, sample_permission,
    ):
        request = api_factory.get("/permissions/")
        force_authenticate(request, user=admin_user)
        response = AllPermissionsView.as_view()(request)
        response.render()
        expected = f"{sample_permission.content_type.app_label}.{sample_permission.codename}"
        assert expected in response.data


class TestRolePermissionsView:
    """Tests for RolePermissionsView."""

    def test_unauthenticated_returns_403(self, api_factory):
        request = api_factory.get("/role-permissions/")
        response = RolePermissionsView.as_view()(request)
        assert response.status_code == 403

    def test_missing_role_returns_400(self, api_factory, regular_user):
        request = api_factory.get("/role-permissions/")
        force_authenticate(request, user=regular_user)
        response = RolePermissionsView.as_view()(request)
        assert response.status_code == 400

    def test_user_without_role_returns_400(self, api_factory, regular_user):
        Group.objects.create(name="editors")
        request = api_factory.get(
            "/role-permissions/", HTTP_ACTIVE_USER_ROLE="editors",
        )
        force_authenticate(request, user=regular_user)
        response = RolePermissionsView.as_view()(request)
        assert response.status_code == 400

    def test_role_via_header_returns_permissions(
        self, api_factory, regular_user, sample_permission,
    ):
        group = Group.objects.create(name="editors")
        group.permissions.add(sample_permission)
        regular_user.groups.add(group)

        request = api_factory.get(
            "/role-permissions/", HTTP_ACTIVE_USER_ROLE="editors",
        )
        force_authenticate(request, user=regular_user)
        response = RolePermissionsView.as_view()(request)
        response.render()

        assert response.status_code == 200
        expected = f"{sample_permission.content_type.app_label}.{sample_permission.codename}"
        assert expected in response.data

    def test_role_via_query_param_returns_permissions(
        self, api_factory, regular_user, sample_permission,
    ):
        group = Group.objects.create(name="viewers")
        group.permissions.add(sample_permission)
        regular_user.groups.add(group)

        request = api_factory.get("/role-permissions/", {"role": "viewers"})
        force_authenticate(request, user=regular_user)
        response = RolePermissionsView.as_view()(request)
        response.render()

        assert response.status_code == 200
        expected = f"{sample_permission.content_type.app_label}.{sample_permission.codename}"
        assert expected in response.data

    def test_role_with_no_permissions_returns_empty(
        self, api_factory, regular_user,
    ):
        group = Group.objects.create(name="empty-role")
        regular_user.groups.add(group)

        request = api_factory.get(
            "/role-permissions/", HTTP_ACTIVE_USER_ROLE="empty-role",
        )
        force_authenticate(request, user=regular_user)
        response = RolePermissionsView.as_view()(request)
        response.render()

        assert response.status_code == 200
        assert response.data == []
