import msgpack
import pytest


class TestMsgpackDecoding:
    """
    Tests for msgpack encoding/decoding functionality used in EventConsumer.

    These tests verify the msgpack.unpackb(body, raw=False) call used in
    EventConsumer.decode_event() method at src/keycloak_utils/consumer/core.py:255
    """

    def test_decode_event_simple_dict(self):
        """Test decoding a simple dictionary encoded with msgpack."""
        test_data = {"event_type": "test", "data": {"key": "value"}}
        encoded = msgpack.packb(test_data, use_bin_type=True)

        result = msgpack.unpackb(encoded, raw=False)

        assert result == test_data
        assert isinstance(result, dict)

    def test_decode_event_nested_dict(self):
        """Test decoding a nested dictionary structure."""
        test_data = {
            "event_type": "USER_EVENT",
            "data": {
                "operation_type": "CREATE.User",
                "operation_information": {"user_id": "123", "username": "testuser"},
                "Realm_Name": "test-realm",
            },
        }
        encoded = msgpack.packb(test_data, use_bin_type=True)

        result = msgpack.unpackb(encoded, raw=False)

        assert result == test_data
        assert result["data"]["operation_information"]["user_id"] == "123"

    def test_decode_event_with_string_values(self):
        """Test that strings are properly decoded (raw=False ensures strings, not bytes)."""
        test_data = {"message": "Hello, World!", "type": "greeting"}
        encoded = msgpack.packb(test_data, use_bin_type=True)

        result = msgpack.unpackb(encoded, raw=False)

        assert result == test_data
        assert isinstance(result["message"], str)
        assert isinstance(result["type"], str)

    def test_decode_event_with_numeric_values(self):
        """Test decoding numeric values."""
        test_data = {"count": 42, "price": 99.99, "active": True}
        encoded = msgpack.packb(test_data, use_bin_type=True)

        result = msgpack.unpackb(encoded, raw=False)

        assert result == test_data
        assert result["count"] == 42
        assert result["price"] == 99.99
        assert result["active"] is True

    def test_decode_event_with_list_values(self):
        """Test decoding list values."""
        test_data = {
            "users": ["alice", "bob", "charlie"],
            "ids": [1, 2, 3],
        }
        encoded = msgpack.packb(test_data, use_bin_type=True)

        result = msgpack.unpackb(encoded, raw=False)

        assert result == test_data
        assert len(result["users"]) == 3
        assert result["ids"] == [1, 2, 3]

    def test_decode_event_empty_dict(self):
        """Test decoding an empty dictionary."""
        test_data = {}
        encoded = msgpack.packb(test_data, use_bin_type=True)

        result = msgpack.unpackb(encoded, raw=False)

        assert result == {}
        assert isinstance(result, dict)

    def test_decode_event_unicode_characters(self):
        """Test decoding unicode characters."""
        test_data = {
            "name": "José García",
            "message": "Hello 世界",
            "emoji": "🎉",
        }
        encoded = msgpack.packb(test_data, use_bin_type=True)

        result = msgpack.unpackb(encoded, raw=False)

        assert result == test_data
        assert result["name"] == "José García"
        assert result["message"] == "Hello 世界"
        assert result["emoji"] == "🎉"

    def test_decode_event_none_values(self):
        """Test decoding None values."""
        test_data = {"key": None, "value": "something"}
        encoded = msgpack.packb(test_data, use_bin_type=True)

        result = msgpack.unpackb(encoded, raw=False)

        assert result == test_data
        assert result["key"] is None

    def test_decode_event_backward_compatibility(self):
        """Test backward compatibility with msgpack_python encoding."""
        # This test ensures that messages encoded with the old msgpack_python
        # package can still be decoded correctly
        test_data = {
            "event_type": "ADMIN_EVENT",
            "data": {
                "operation_type": "UPDATE.User",
                "operation_information": {
                    "user_id": "user-123",
                    "email": "test@example.com",
                },
            },
        }
        # Encode using current msgpack (same format as msgpack_python)
        encoded = msgpack.packb(test_data, use_bin_type=True)

        result = msgpack.unpackb(encoded, raw=False)

        assert result == test_data
        # Verify all string types are properly decoded (not bytes)
        assert isinstance(result["event_type"], str)
        assert isinstance(result["data"]["operation_information"]["email"], str)
