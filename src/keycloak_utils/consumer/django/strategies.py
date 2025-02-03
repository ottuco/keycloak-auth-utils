import logging
from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Optional, Tuple, Type

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType

from ...contrib.django.conf import KC_UTILS_KC_CLIENT_ID, KC_UTILS_KC_REALM
from ...sync.kc_admin import kc_admin

logger = logging.getLogger("keycloak_event_consumer")
User = get_user_model()


class EventStrategy(ABC):
    ms_name: str = KC_UTILS_KC_CLIENT_ID

    def process(self, event_data: Dict, operation_type: str, event_type: str):
        """
        Processes an event based on its data, operation type, and event type.

        Args:
            event_data (Dict): The event data containing operation information.
            operation_type (str): The type of operation (e.g., 'CREATE', 'UPDATE', 'DELETE').
            event_type (str): The type of event (e.g., 'Permission', 'Role', 'User').

        Functionality:
            - Validates the event data.
            - Retrieves the event information based on the event type.
            - Executes the corresponding operation strategy (CREATE, UPDATE, DELETE).
        """
        if not self._validate_event(event_data) or not (
            event_info := self._get_event_info(event_data["data"], event_type)
        ):
            return
        operation_strategy = self._get_operation_strategy(operation_type)
        operation_strategy(*event_info)

    def _validate_event(self, event_data: Dict) -> bool:
        """
        Validates the event data to ensure it contains the necessary information.

        Args:
            event_data (Dict): The event data to validate.

        Returns:
            bool: True if the event data is valid, otherwise False.
        """

        if "operation_information" not in event_data["data"].keys():
            logger.warning(
                f"the event data that failed with no operation_information key is {event_data}",
            )
            return False

        return True

    @staticmethod
    def _get_model_class(app_label: str, model_name: str) -> Optional[Type]:
        """
        Fetches the model class dynamically based on the app label and model name.

        Args:
            app_label (str): The app label where the model is located.
            model_name (str): The name of the model.

        Returns:
            Optional[Type]: The model class if found, otherwise None.
        """
        try:
            return apps.get_model(app_label, model_name)
        except Exception as e:
            logger.error(f"Error fetching model {app_label}.{model_name}: {e}")
            return None

    @staticmethod
    def _get_content_type_for_model(model: Type) -> ContentType:
        """
        Retrieves the content type for a given model.

        Args:
                model (Type): The model class.

        Returns:
                ContentType: The content type associated with the model.
        """
        return ContentType.objects.get_for_model(model)

    @staticmethod
    def _handle_groups(roles: List):
        """
        Handles the creation or retrieval of user groups based on roles.

        Args:
            roles (List): A list of roles to be converted into groups.
        """
        from django.contrib.auth.models import Group

        for group_name in roles:
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                logger.info(f"Group '{group_name}' created successfully")
            else:
                logger.info(f"Group '{group_name}' already exists")

    @staticmethod
    def _handle_default(*args):
        """
        Handles unknown operations by logging a warning.

        Args:
            *args: Any additional arguments.
        """
        logger.warning(f"Unknown operation")

    def _get_event_info(self, event_data: Dict, event_type: str) -> Optional[Dict]:
        """
        Retrieves event information based on the event type.

        Args:
            event_data (Dict): The event data to extract information from.
            event_type (str): The type of event (e.g., 'Permission', 'Role', 'User').

        Returns:
            Optional[Dict]: The extracted event information, or None if not applicable.
        """
        event_strategy_map = {
            "Permission": self._get_permission_info,
            "Role": self._get_role_info,
            "User": self._get_user_info,
        }
        return event_strategy_map[event_type](event_data)

    def _get_permission_info(self, event_data: Dict) -> Optional[Tuple]:
        """
        Extracts permission-related information from the event data.

        Args:
            event_data (Dict): The event data containing permission information.

        Returns:
            Optional[Tuple]: A tuple containing permission-related information, or None if not valid.
        """
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
                f"the permission info {permission_info} is not formatted correctly, the format should be app.model.codename",
            )
            raise ke

    def _get_role_info(self, event_data: Dict) -> Optional[Tuple]:
        """
        Extracts role-related information from the event data.

        Args:
            event_data (Dict): The event data containing role information.

        Returns:
            Optional[Tuple]: A tuple containing role-related information, or None if not valid.
        """
        role = event_data["operation_information"]
        if role["client"] != self.ms_name:
            return
        group_name = role["role_name"]
        role_id = role["role_id"]
        return group_name, role_id

    def _get_user_info(self, event_data: Dict) -> Optional[Tuple]:
        """
        Extracts user-related information from the event data.

        Args:
            event_data (Dict): The event data containing user information.

        Returns:
            Optional[Tuple]: A tuple containing user-related information, or None if not valid.
        """
        kc_admin.connection.realm_name = KC_UTILS_KC_REALM
        clients = kc_admin.get_clients()
        if not any(
            client.get("clientId") == KC_UTILS_KC_CLIENT_ID for client in clients
        ):
            return
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
    def _handle_create(self, *args) -> None: ...

    @abstractmethod
    def _handle_update(self, *args) -> None: ...

    @abstractmethod
    def _handle_delete(self, *args) -> None: ...

    def _get_operation_strategy(self, operation_type: str) -> Callable:
        """
        Retrieves the appropriate strategy for the given operation type.

        Args:
            operation_type (str): The type of operation (e.g., 'CREATE', 'UPDATE', 'DELETE').

        Returns:
            Callable: The function that handles the operation type.
        """

        if operation_type == "ASSIGN":
            operation_type = "CREATE"
        strategies = {
            "CREATE": self._handle_create,
            "UPDATE": self._handle_update,
            "DELETE": self._handle_delete,
        }
        return strategies.get(operation_type, self._handle_default)


class RoleEventStrategy(EventStrategy):
    """
    Strategy to handle events related to roles, such as create and delete operations.
    """

    def __init__(self):
        """
        Initializes the RoleEventStrategy by calling the parent class constructor.
        """
        super().__init__()
        # self.kc_role = KeycloakRole()  # Placeholder for keycloak role handling

    def _handle_create(self, group_name: str, role_id: str):
        """
        Handles the creation of a group.

        Args:
            group_name (str): The name of the group to be created.
            role_id (str): The ID of the associated role.

        Logs:
            Info: Successfully created a group with the provided name.
            Error: If the group creation fails.
        """
        try:
            group = Group.objects.create(name=group_name)
            logger.info(f"created group {group}")
            # self.kc_role.get_or_create_policy(group, role_id)  # Placeholder for policy creation
        except Exception as e:
            logger.error(f"Error creating group {group_name}: {e}")

    def _handle_update(self):
        """
        Placeholder method for handling updates on groups.
        """
        pass

    def _handle_delete(self, group_name: str, role_id: str):
        """
        Handles the deletion of a group.

        Args:
            group_name (str): The name of the group to be deleted.
            role_id (str): The ID of the associated role.

        Logs:
            Info: Successfully deleted the group.
            Error: If the group deletion fails.
        """
        try:
            group = Group.objects.get(name=group_name)
            # self.kc_role.delete_policy(group)  # Placeholder for policy deletion
            group.delete()
            logger.info(f"group {group_name} deleted")
        except Exception as e:
            logger.error(f"Error deleting group {group_name}: {e}")


class UserEventStrategy(EventStrategy):
    """
    Strategy to handle events related to users, such as create, update, and delete operations.
    """

    def _handle_create(
        self,
        kc_user: Dict,
        roles: List,
        timezone: str,
        is_superuser: bool,
    ):
        """
        Handles the creation of a new user.

        Args:
            kc_user (Dict): User details from Keycloak.
            roles (List): A list of roles to assign to the user.
            timezone (str): The user's timezone.
            is_superuser (bool): Whether the user is a superuser.

        Logs:
            Info: Successfully created a new user with the provided details.
            Error: If user creation fails.
        """
        user = User.objects.create(
            username=kc_user["username"],
            first_name=kc_user["firstName"],
            last_name=kc_user["lastName"],
            email=kc_user["email"],
            kc_id=kc_user["user_id"],
        )
        logger.info(f"created user {user}")

    def _handle_update(
        self,
        kc_user: Dict,
        roles: List,
        timezone: str,
        is_superuser: bool,
    ):
        """
        Handles the update of an existing user.

        Args:
            kc_user (Dict): User details from Keycloak.
            roles (List): A list of roles to assign to the user.
            timezone (str): The user's timezone.
            is_superuser (bool): Whether the user is a superuser.

        Logs:
            Info: Successfully updated the user.
            Error: If user update fails or user does not exist.
        """
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
                f"User with username {kc_user['username']} and kc_id {kc_user['user_id']} does not exist.",
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

    def _handle_delete(self, *args):
        """
        Placeholder method for handling the deletion of a user.
        """
        pass


class PermissionEventStrategy(EventStrategy):
    """
    Strategy for handling permission-related events such as creation, update, and assignment to groups.
    """

    def _format_camel_case(self, text: str) -> str:
        """
        Converts a camel case string to a human-readable format by separating the words with spaces.

        Args:
            text (str): The camel case string to be formatted.

        Returns:
            str: The formatted string with spaces separating words.
        """
        import re

        segments = re.findall(r"[A-Z][a-z]*", text)

        if len(segments) > 1:
            return " ".join(segments)
        else:
            return segments[0]

    def _handle_create(
        self,
        permission_app: str,
        permission_codename: str,
        permission_model: str,
        groups_names: List[str],
    ):
        """
        Handles the creation of a new permission for a specific model and codename.

        Args:
            permission_app (str): The app where the permission belongs.
            permission_codename (str): The codename of the permission.
            permission_model (str): The model associated with the permission.
            groups_names (List[str]): The list of group names to assign the permission to.

        Logs:
            Info: Whether the permission was created or already exists.
            Warning/Error: If content type or permission creation fails.
        """
        try:
            content_type = ContentType.objects.get(
                app_label=permission_app,
                model=permission_model.lower(),
            )
            model_name = self._format_camel_case(content_type.model_class().__name__)
            action = permission_codename.split("_")[0]
            permission_name = f"Can {action} {model_name}"
        except ContentType.DoesNotExist:
            logger.warning(
                f"no content type match {permission_app} and {permission_model}... breaking",
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
        permission_app: str,
        permission_codename: str,
        permission_model: str,
        groups_names: List[str],
    ):
        """
        Handles the update of an existing permission.

        Args:
            permission_app (str): The app where the permission belongs.
            permission_codename (str): The codename of the permission.
            permission_model (str): The model associated with the permission.
            groups_names (List[str]): The list of group names to update permissions for.

        Logs:
            Info: If the permission is successfully updated or not registered.
        """
        logger.info(
            f"Updating permission {permission_codename} in {permission_app} related group",
        )

        try:
            permission = Permission.objects.get(
                codename=permission_codename,
                content_type__app_label=permission_app,
            )
        except Permission.DoesNotExist:
            logger.info(f"Permission {permission_codename} is not registered")
            return

        self._update_groups_perms(permission, groups_names)

    def _update_groups_perms(
        self,
        permission: Permission,
        groups_names: List[str],
    ) -> None:
        """
        Updates the permission assignments for specific groups.

        Args:
            permission (Permission): The permission to be assigned or removed.
            groups_names (List[str]): The list of group names to add or remove the permission from.

        Logs:
            Info: Success or failure of adding/removing the permission from groups.
        """
        add_perm_groups = Group.objects.filter(name__in=groups_names).exclude(
            permissions=permission,
        )
        remove_perm_groups = Group.objects.filter(permissions=permission).exclude(
            name__in=groups_names,
        )

        if remove_perm_groups:
            list(
                map(
                    lambda group: group.permissions.remove(permission),
                    remove_perm_groups,
                ),
            )
            logger.info(
                f"Removed permission {permission} from groups {remove_perm_groups}",
            )
        else:
            logger.info("No groups need this permission removed")

        if add_perm_groups:
            list(
                map(
                    lambda group: group.permissions.add(permission),
                    add_perm_groups,
                ),
            )
            logger.info(f"Added permission {permission} to groups {add_perm_groups}")
        else:
            logger.info("No groups need this permission added.")

    def _handle_delete(self):
        """
        Placeholder method for handling the deletion of a permission.
        """
        pass


class BaseEventStrategyFactory:
    """
    Base class for event strategy factories, ensuring the event map is defined in subclasses.
    """

    def __init_subclass__(cls, **kwargs):
        """
        Ensures that the subclass defines an 'event_map' as a dictionary.

        Args:
            kwargs: Additional keyword arguments.

        Raises:
            AttributeError: If the subclass does not define the 'event_map' attribute.
        """
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, "event_map") or not isinstance(cls.event_map, dict):
            raise AttributeError(
                f"Subclass '{cls.__name__}' must define an 'event_map' as a dictionary.",
            )

    def handle_event_type(self, event_type: str) -> Callable:
        """
        Handles an event type by mapping it to the appropriate strategy.

        Args:
            event_type (str): The event type to be handled.

        Returns:
            Callable: The strategy handler for the event type.

        Raises:
            KeyError: If the event type is not found in the event map.
        """
        logger.info(
            f"the event_type in the factory {self.__class__.__name__} is {event_type} event, {self.event_map[event_type].__name__} will handle it!",
        )
        if event_type not in self.event_map.keys():
            raise KeyError(f'the event_type "{event_type}" is not registered')

        return self.event_map[event_type]()


class KCEventStrategyFactory(BaseEventStrategyFactory):
    """
    Factory for handling Keycloak-related events, mapping event types to corresponding strategies.
    """

    event_map = {
        "Permission": PermissionEventStrategy,
        "Role": RoleEventStrategy,
        "User": UserEventStrategy,
    }


class PaymentEventStrategyFactory(BaseEventStrategyFactory):
    """
    Placeholder factory for handling payment-related events.
    """

    event_map = {}


class EventTypeStrategyClassFactory(BaseEventStrategyFactory):
    """
    Factory for handling different event categories (e.g., payment, Keycloak) and mapping them to specific factories.
    """

    event_map = {
        "payment": PaymentEventStrategyFactory,
        "kc": KCEventStrategyFactory,
    }
