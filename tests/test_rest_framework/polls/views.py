from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .authentication import (
    BearerAuthentication,
    DynamicAuthentication,
    RandomAuthentication,
    TokenAuthentication,
)


class UserTestAPI(APIView):
    authentication_classes = [
        BearerAuthentication,
        DynamicAuthentication,
        TokenAuthentication,
        RandomAuthentication,
    ]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return Response(
            {
                "message": "Hello, world!",
                "user": request.user.username,
            },
        )
