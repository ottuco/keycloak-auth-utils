import logging
from abc import ABC, abstractmethod
from typing import Optional, Type

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType

from ...contrib.django.conf import KC_UTILS_KC_CLIENT_ID

logger = logging.getLogger("keycloak_event_consumer")
User = get_user_model()


class EventStrategy(ABC):
    ms_name = KC_UTILS_KC_CLIENT_ID

    def process(self, event_data, operation_type, event_type):
        if not self._validate_event(event_data):
            return

        operation_strategy = self._get_operation_strategy(operation_type)
        event_info = self._get_event_info(event_data["data"], event_type)
        if event_info is None:
            return
        operation_strategy(*event_info)

    def _validate_event(self, event_data):
        if "operation_information" not in event_data["data"].keys():
            logger.warning(
                f"the event data that failed with no operation_information key is {event_data}"
            )
            return False

        return True

    @staticmethod
    def _get_model_class(app_label: str, model_name: str) -> Optional[Type]:
        """Fetch the model class dynamically."""
        try:
            return apps.get_model(app_label, model_name)
        except Exception as e:
            logger.error(f"Error fetching model {app_label}.{model_name}: {e}")
            return None

    @staticmethod
    def _get_content_type_for_model(model: Type) -> ContentType:
        """Fetch the content type for a given model."""
        return ContentType.objects.get_for_model(model)

    @staticmethod
    def _handle_groups(roles):
        from django.contrib.auth.models import Group

        for group_name in roles:
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                logger.info(f"Group '{group_name}' created successfully")
            else:
                logger.info(f"Group '{group_name}' already exists")

    @staticmethod
    def _handle_default(*args):
        logger.warning(f"Unknown operation")

    def _get_event_info(self, event_data, event_type):
        event_strategy_map = {
            "Permission": self._get_permission_info,
            "Role": self._get_role_info,
            "User": self._get_user_info,
        }
        return event_strategy_map[event_type](event_data)

    def _get_permission_info(self, event_data):
        if event_data["Client_Name"] != self.ms_name:
            return
        operation_info = event_data["operation_information"]
        policies = operation_info["apply_policy"]
        groups = [policy.replace("Policy", "") for policy in policies]
        permission_info = operation_info["name"]
        try:
            permission_codename = permission_info.split(".")[2]
            permission_app = permission_info.split(".")[0]
            permission_model = permission_info.split(".")[1]
            return (
                permission_app,
                permission_codename,
                permission_model,
                groups,
            )
        except KeyError as ke:
            logger.error(
                f"the permission info {permission_info} is not formatted correctly, the format should be app.model.codename"
            )
            raise ke

    def _get_role_info(self, event_data):
        role = event_data["operation_information"]
        if role["client"] != self.ms_name:
            return
        group_name = role["role_name"]
        role_id = role["role_id"]
        return group_name, role_id

    def _get_user_info(self, event_data):
        user = event_data["operation_information"]
        payout_roles = (
            user["roles"].get(self.ms_name, [])
            if isinstance(user["roles"], dict)
            else []
        )
        roles_names = [role["name"] for role in payout_roles]
        timezone = next(
            (
                attr["timezone"]
                for attr in user.get("attributes", [])
                if isinstance(attr, dict) and "timezone" in attr
            ),
            None,
        )
        is_superuser = "super_admin" in roles_names
        return user, roles_names, timezone, is_superuser

    @abstractmethod
    def _handle_create(self, *args): ...

    @abstractmethod
    def _handle_update(self, *args): ...

    @abstractmethod
    def _handle_delete(self, *args): ...

    def _get_operation_strategy(self, operation_type):
        if operation_type == "ASSIGN":
            operation_type = "CREATE"
        strategies = {
            "CREATE": self._handle_create,
            "UPDATE": self._handle_update,
            "DELETE": self._handle_delete,
        }
        return strategies.get(operation_type, self._handle_default)


class RoleEventStrategy(EventStrategy):
    def __init__(self):
        super().__init__()
        # self.kc_role = KeycloakRole()

    def _handle_create(self, group_name, role_id):
        try:
            group = Group.objects.create(name=group_name)
            logger.info(f"created group {group}")
            # self.kc_role.get_or_create_policy(group, role_id)
        except Exception as e:
            logger.error(f"Error creating group {group_name}: {e}")

    def _handle_update(self): ...

    def _handle_delete(self, group_name, *args):
        try:
            group = Group.objects.get(name=group_name)
            # self.kc_role.delete_policy(group)
            group.delete()
            logger.info(f"group {group_name} deleted")
        except Exception as e:
            logger.error(f"Error deleting group {group_name}: {e}")


class UserEventStrategy(EventStrategy):
    def __init__(self):
        super().__init__()

    def _handle_create(self, kc_user, roles, timezone, is_superuser):
        user = User.objects.create(
            username=kc_user["username"],
            first_name=kc_user["firstName"],
            last_name=kc_user["lastName"],
            email=kc_user["email"],
            kc_id=kc_user["user_id"],
        )
        logger.info(f"created user {user}")

    def _handle_update(self, kc_user, roles, timezone, is_superuser):
        user = None
        for field, value in [
            ("username", kc_user["username"]),
            ("kc_id", kc_user["user_id"]),
        ]:
            try:
                user = User.objects.get(**{field: value})
                break
            except User.DoesNotExist:
                logger.info(f"User not found by {field}: '{value}'")
                continue

        if not user:
            logger.error(
                f"User with username {kc_user['username']} and kc_id {kc_user['user_id']} does not exist."
            )
            return

        user.username = kc_user["username"]
        user.first_name = kc_user["firstName"]
        user.last_name = kc_user["lastName"]
        user.is_active = kc_user["enabled"]
        user.email = kc_user["email"]
        setattr(user, "timezone", timezone)
        user.is_superuser = is_superuser
        user_groups = Group.objects.filter(name__in=roles)
        user.groups.set(user_groups)
        user.save()
        logger.info(f"user {kc_user['username']} updated")

    def _handle_delete(self, *args): ...


class PermissionEventStrategy(EventStrategy):
    def _format_camel_case(self, text):
        import re

        segments = re.findall(r"[A-Z][a-z]*", text)

        if len(segments) > 1:
            return " ".join(segments)
        else:
            return segments[0]

    def _handle_create(
        self,
        permission_app,
        permission_codename,
        permission_model,
        groups_names,
    ):
        try:
            content_type = ContentType.objects.get(
                app_label=permission_app, model=permission_model.lower()
            )
            model_name = self._format_camel_case(content_type.model_class().__name__)
            action = permission_codename.split("_")[0]
            permission_name = f"Can {action} {model_name}"
        except ContentType.DoesNotExist:
            logger.warning(
                f"no content type match {permission_app} and {permission_model}... breaking"
            )
            return
        except Exception as e:
            logger.error(e)
            return

        permission, created = Permission.objects.get_or_create(
            content_type=content_type,
            codename=permission_codename,
        )
        if created:
            permission.name = permission_name
            permission.save()
            logger.info(f"permission {permission_name} created")
        else:
            logger.info(f"permission {permission_name} already exists")
        self._update_groups_perms(permission, groups_names)

    def _handle_update(
        self,
        permission_app,
        permission_codename,
        permission_model,
        groups_names,
    ):
        logger.info(
            f"Updating permission {permission_codename} in {permission_app} related group"
        )

        try:
            permission = Permission.objects.get(
                codename=permission_codename, content_type__app_label=permission_app
            )
        except Permission.DoesNotExist:
            logger.info(f"Permission {permission_codename} is not registered")
            return

        self._update_groups_perms(permission, groups_names)

    def _update_groups_perms(self, permission, groups_names):
        add_perm_groups = Group.objects.filter(name__in=groups_names).exclude(
            permissions=permission
        )
        remove_perm_groups = Group.objects.filter(permissions=permission).exclude(
            name__in=groups_names
        )

        if remove_perm_groups:
            list(
                map(
                    lambda group: group.permissions.remove(permission),
                    remove_perm_groups,
                )
            )
            logger.info(
                f"Removed permission {permission} from groups {remove_perm_groups}"
            )
        else:
            logger.info("No groups need this permission removed")

        if add_perm_groups:
            list(
                map(
                    lambda group: group.permissions.add(permission),
                    add_perm_groups,
                )
            )
            logger.info(f"Added permission {permission} to groups {add_perm_groups}")
        else:
            logger.info("No groups need this permission added.")

    def _handle_delete(self): ...


class BaseEventStrategyFactory:
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, "event_map") or not isinstance(cls.event_map, dict):
            raise AttributeError(
                f"Subclass '{cls.__name__}' must define an 'event_map' as a dictionary."
            )

    def handle_event_type(self, event_type):
        logger.info(
            f"the event_type in the factory {self.__class__.__name__} is {event_type} event, {self.event_map[event_type].__name__} will handle it!"
        )
        if event_type not in self.event_map.keys():
            raise KeyError(f'the event_type "{event_type}" is not registered')

        return self.event_map[event_type]()


class KCEventStrategyFactory(BaseEventStrategyFactory):
    event_map = {
        "Permission": PermissionEventStrategy,
        "Role": RoleEventStrategy,
        "User": UserEventStrategy,
    }


class PaymentEventStrategyFactory(BaseEventStrategyFactory):
    event_map = {}


class EventTypeStrategyClassFactory(BaseEventStrategyFactory):
    event_map = {
        "payment": PaymentEventStrategyFactory,
        "kc": KCEventStrategyFactory,
    }
