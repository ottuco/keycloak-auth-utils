"""Tests for keycloak_utils.contrib.django.views."""

import pytest
from django.test import RequestFactory

from keycloak_utils.contrib.django.views import ErrorView

pytestmark = pytest.mark.django_db


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
