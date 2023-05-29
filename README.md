# keycloak auth utils

## Installation

### 1. Django/DRF

```bash
pip install git+https://github.com/ottuco/keycloak-auth-utils#egg=keycloak-utils[django]
```

### 2. FastAPI

```bash
pip install git+https://github.com/ottuco/keycloak-auth-utils#egg=keycloak-utils[fastapi]
````

## Usage

### 1. Django/DRF

```python
# authentication.py
from django.contrib.auth import get_user_model
from keycloak_utils.authentication.rest_framework import BaseDRFKCAuthentication

User = get_user_model()


class KeycloakDRFAuthentication(BaseDRFKCAuthentication):
    kc_host = "http://localhost:8080"
    kc_realm = "your-realm-nae"
    kc_algorithms = ["RS256"]
    kc_audience = "account"

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


class AuthenticationMiddleware(BaseFastAPIKCAuthentication):
    kc_host = "http://localhost:8080"
    kc_realm = "your-realm-nae"
    kc_algorithms = ["RS256"]
    kc_audience = "account"

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
```
