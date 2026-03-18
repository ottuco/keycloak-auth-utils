from django.contrib.auth.models import Permission
from rest_framework import serializers


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ()

    def to_representation(self, obj: Permission) -> str:
        return f"{obj.content_type.app_label}.{obj.codename}"
