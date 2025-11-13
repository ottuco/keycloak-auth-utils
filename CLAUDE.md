# Claude Code Context - keycloak-auth-utils

## Project Overview

`keycloak-auth-utils` is a Python library that provides helper classes for Keycloak authentication in Django/DRF and FastAPI applications. It also includes utilities for syncing Keycloak users, roles, and permissions, as well as consuming Keycloak events via RabbitMQ.

## Key Components

### 1. Authentication

#### Django/DRF (`src/keycloak_utils/authentication/rest_framework.py`)
- `BaseDRFKCAuthentication`: Base authentication class for Django REST Framework
- Validates JWT tokens from Keycloak
- Supports custom auth schemes (Bearer, Token, etc.)
- Users implement `get_or_create_user()` to handle user creation

#### FastAPI (`src/keycloak_utils/authentication/fastapi.py`)
- `BaseFastAPIKCAuthentication`: Middleware for FastAPI
- `FastAPIKeycloakAuthBackend`: Backend for validating tokens
- Supports multiple authentication backends

### 2. Event Consumer (`src/keycloak_utils/consumer/core.py`)

The `EventConsumer` class handles RabbitMQ messages from Keycloak:
- **EventHandler**: Processes event messages and determines appropriate strategies
- **EventConsumer**: Extends EventHandler to consume from RabbitMQ queues
- **decode_event()**: Decodes msgpack-encoded messages at [core.py:255](src/keycloak_utils/consumer/core.py#L255)

#### Message Flow
1. Receives msgpack-encoded events from RabbitMQ
2. Decodes using `msgpack.unpackb(body, raw=False)`
3. Routes to appropriate strategy based on event type
4. Processes user/role/permission changes

### 3. Sync Utilities (`src/keycloak_utils/sync/`)

Celery tasks for syncing Django data to Keycloak:
- **KeycloakBase**: Initialize realm and clients
- **KeycloakRole**: Sync Django groups to Keycloak roles
- **KeycloakUser**: Sync Django users to Keycloak
- **KeycloakPermission**: Sync Django permissions to Keycloak

## Project Structure

```
keycloak-auth-utils/
├── src/keycloak_utils/
│   ├── authentication/          # Auth backends for Django/FastAPI
│   ├── backend/                 # Backend implementations
│   ├── consumer/                # RabbitMQ event consumer
│   ├── contrib/django/          # Django-specific utilities
│   ├── manager/                 # Public key management
│   └── sync/                    # Sync utilities
├── tests/
│   ├── test_rest_framework/     # Django/DRF tests
│   └── test_fastapi/            # FastAPI tests
├── pyproject.toml               # Project configuration
└── README.md                    # Documentation
```

## Testing

### Current Test Coverage (34 tests)
- **Authentication tests** ([tests/test_rest_framework/tests/test_authentication.py](tests/test_rest_framework/tests/test_authentication.py)): 6 tests
- **XSS protection tests** ([tests/test_rest_framework/tests/test_contrib_views.py](tests/test_rest_framework/tests/test_contrib_views.py)): 10 tests
- **View authentication tests** ([tests/test_rest_framework/tests/test_views.py](tests/test_rest_framework/tests/test_views.py)): 9 tests
- **Msgpack tests** ([tests/test_rest_framework/tests/test_consumer.py](tests/test_rest_framework/tests/test_consumer.py)): 9 tests

### Running Tests
```bash
# Django tests
make test-django

# Or directly with pytest
PYTHONPATH=. .venv/bin/pytest tests/test_rest_framework/ -v
```

## Dependencies

### Core Dependencies ([pyproject.toml:40-48](pyproject.toml#L40-L48))
- `requests>=2.31.0` - HTTP library
- `pyjwt[crypto]>=2.8.0` - JWT token handling
- `python-keycloak>=4.6.2` - Keycloak client
- `pika>=1.3.2` - RabbitMQ client
- `msgpack>=1.0.0` - Message serialization (for EventConsumer)
- `pydantic>=1.10.12` - Data validation
- `httpx>=0.24.0` - Async HTTP client
- `asgiref>=3.6.0` - ASGI utilities

### Optional Dependencies
- `[django]`: Django REST Framework support
- `[fastapi]`: FastAPI support
- `[django-sync]`: Celery sync functionality
- `[all]`: All features

## Python Support

- Requires Python 3.7+
- Tested on Python 3.7, 3.8, 3.9, 3.10

## Common Development Tasks

### Running Pre-commit Hooks
```bash
make pre-commit
```

### Formatting Code
```bash
make format
```

### Creating a Release
```bash
# Dry run
bump2version --dry-run --verbose [major|minor|patch]

# Actual release
bump2version --verbose [major|minor|patch]
git push origin main --tags
```

## Important Code Locations

### Authentication
- DRF Auth: [src/keycloak_utils/authentication/rest_framework.py](src/keycloak_utils/authentication/rest_framework.py)
- FastAPI Auth: [src/keycloak_utils/authentication/fastapi.py](src/keycloak_utils/authentication/fastapi.py)

### Event Consumer
- Main consumer: [src/keycloak_utils/consumer/core.py](src/keycloak_utils/consumer/core.py)
- msgpack decode: [src/keycloak_utils/consumer/core.py:255](src/keycloak_utils/consumer/core.py#L255)

### Configuration
- Django settings: [src/keycloak_utils/contrib/django/conf.py](src/keycloak_utils/contrib/django/conf.py)

## Environment Variables

Key environment variables for configuration:
- `KC_UTILS_KC_SERVER_URL` - Keycloak server URL
- `KC_UTILS_KC_REALM` - Keycloak realm name
- `KC_UTILS_KC_CLIENT_ID` - Client ID
- `KC_UTILS_KC_CLIENT_SECRET` - Client secret
- `RABBITMQ_URL` - RabbitMQ connection URL
- `KC_UTILS_CREATE_QUEUES` - Queues to create (dict)
- `KC_UTILS_CONSUMER_QUEUES` - Queues to consume (dict)
- `KC_UTILS_MESSAGE_MAX_RETRIES` - Max message retries (default: 10)

## Recent Changes

### v0.12.1
- Fixed XSS vulnerability in ErrorView
- Added CONTRIBUTING.md
- Migrated from deprecated `msgpack_python` to `msgpack>=1.0.0`
- Added comprehensive msgpack encoding/decoding tests

## Known Issues

- The codebase uses Python 3.10+ union syntax (`dict | str`) in some places while claiming to support Python 3.7+
- EventConsumer class cannot be imported in Python 3.7-3.9 due to this incompatibility

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
