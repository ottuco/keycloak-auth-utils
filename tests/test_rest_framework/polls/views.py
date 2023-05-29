from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .authentication import CustomDRFKCAuthentication


class UserTestAPI(APIView):
    authentication_classes = [CustomDRFKCAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return Response(
            {
                "message": "Hello, world!",
                "user": request.user.username,
            },
        )
