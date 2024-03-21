# keycloak auth utils

## Installation

### 1. Django/DRF

```bash
pip install keycloak-utils[django]
```

### 2. FastAPI

```bash
pip install keycloak-utils[fastapi]
````

## Usage

### 1. Django/DRF

```python
# authentication.py
from django.contrib.auth import get_user_model
from keycloak_utils.authentication.rest_framework import BaseDRFKCAuthentication

User = get_user_model()


class KeycloakDRFAuthentication(BaseDRFKCAuthentication):
    kc_host = "localhost:8443"
    kc_realm = "your-realm-nae"
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Bearer"

    def get_or_create_user(self, claims: dict):
        # override this method to get or create user
        # return User.objects.get_or_create(email=claims["email"])
        return user_instance


# views.py
from rest_framework.views import APIView

class TestView(APIView):
    authentication_classes = [KeycloakDRFAuthentication] # Add authentication class here

    def get(self, request):
        return Response({"message": "Hello, world!"})
```

### 2. FastAPI

```python
# middlewares.py
import typing

from fastapi import Request
from keycloak_utils.authentication.fastapi import BaseFastAPIKCAuthentication
from keycloak_utils.backend.fastapi import FastAPIKeycloakAuthBackend

class BearerAuthBackend(FastAPIKeycloakAuthBackend):
    kc_host = "localhost:8443"
    kc_realm = "test"
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Bearer"


class AuthenticationMiddleware(BaseFastAPIKCAuthentication):
    backends = [BearerAuthBackend]

    def post_process_claims(
            self,
            claims: typing.Optional[dict],
            request: Request,
    ) -> Request:
        # do something with `claims` here
        return request


# main.py
from fastapi import FastAPI

app = FastAPI()

app.add_middleware(AuthenticationMiddleware) # Add middleware here


@app.get("/")
def read_root():
    return {"Hello": "World"}

```
## Example cURL request

```bash
curl --location 'https://localhost:8443/path/to/resource/' \
--header 'Authorization: <AUTH_SCHEME> <JWT_ACCESS_TOKEN>'
```
* Replace the
  * `JWT_ACCESS_TOKEN` with the actual access token.
  * `AUTH_SCHEME` with the actual auth scheme. For example, `Bearer` or `Token` or anything you defined with `auth_scheme` class attribute.

## Usage Advanced

### 1. Support for multiple authentication classes/backends

#### Django/DRF

```python
# authentication.py
from django.contrib.auth import get_user_model
from keycloak_utils.authentication.rest_framework import BaseDRFKCAuthentication

User = get_user_model()


class KCBearerAuth(BaseDRFKCAuthentication):
    kc_host = "localhost:8443"
    kc_realm = "your-realm-nae"
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Bearer"

    def get_or_create_user(self, claims: dict):
        # override this method to get or create user
        # return User.objects.get_or_create(email=claims["email"])
        return user_instance

class KCRandomAuth(BaseDRFKCAuthentication):
    kc_host = "localhost:1234" # using a different KeyCloak host
    kc_realm = "realm-2" # using a different realm
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Random" # This should be unique across all the authentication classes

    def get_or_create_user(self, claims: dict):
        # override this method to get or create user
        # return User.objects.get_or_create(email=claims["email"])
        return user_instance


# views.py
from rest_framework.views import APIView

class TestView(APIView):
    authentication_classes = [KCBearerAuth, KCRandomAuth] # Add authentication class here

    def get(self, request):
        return Response({"message": "Hello, world!"})
```

#### FastAPI
```python
# middlewares.py
import typing

from fastapi import Request
from keycloak_utils.authentication.fastapi import BaseFastAPIKCAuthentication
from keycloak_utils.backend.fastapi import FastAPIKeycloakAuthBackend

class BearerAuthBackend(FastAPIKeycloakAuthBackend):
    kc_host = "localhost:8443"
    kc_realm = "test"
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Bearer"

class RandomAuthBackend(FastAPIKeycloakAuthBackend):
    kc_host = "localhost:1234" # using a different KeyCloak host
    kc_realm = "realm-2" # using a different realm
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Random"

class AuthenticationMiddleware(BaseFastAPIKCAuthentication):
    backends = [BearerAuthBackend, RandomAuthBackend]

    def post_process_claims(
            self,
            claims: typing.Optional[dict],
            request: Request,
    ) -> Request:
        # do something with `claims` here
        return request


# main.py
from fastapi import FastAPI

app = FastAPI()

app.add_middleware(AuthenticationMiddleware) # Add middleware here


@app.get("/")
def read_root():
    return {"Hello": "World"}

```

### 2. Login into Django Using Keycloak SSO.
Add following settings in django app settings.py
```python
KC_UTILS_KC_HOST = "keycloak.sso.com"
KC_UTILS_KC_REALM = "myapp.example.com"
KC_UTILS_KC_ALGORITHMS = ["RS256"]
KC_UTILS_KC_AUDIENCE = "account"
KC_UTILS_AUTH_SCHEME = "Bearer"
KC_UTILS_OIDC_RP_CLIENT_ID = "account"
KC_UTILS_OIDC_RP_CLIENT_SECRET = "client_secret"

ADMIN_URL = "admin"

AUTHENTICATION_BACKENDS = (
    "django.contrib.auth.backends.ModelBackend",
    "keycloak_utils.contrib.django.auth.AuthenticationBackend"
)
```

Add following in urls.py
```python
from django.conf import settings
from django.contrib import admin
from django.urls import include, path


urlpatterns = [
    path("", include("keycloak_utils.contrib.django.urls")),
    path(f"{settings.ADMIN_URL}/", admin.site.urls),
]
```

Start app server and navigate to login url, It will redirect to SSO login page.
```
http://localhost:8000/admin/
```


## Test

```bash
# Install the dependencies
pip install .[test]

# Run tests
python -m pytest
```

## Release
```base
# do a dry-run first -
bump2version --dry-run --verbose [major|minor|patch]

# if everything looks good, run the following command to release
bump2version --verbose [major|minor|patch]

# push the changes to remote
git push origin master --tags
```
