import base64
import logging
from abc import abstractmethod
from dataclasses import dataclass, field
from functools import wraps
from itertools import chain
from typing import Any, Callable, Dict, Generator, List, Optional, cast

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.db.models import Q, QuerySet

from ...contrib.django.conf import KC_UTILS_KC_CLIENT_ID
from ..kc_admin import kc_admin

logger = logging.getLogger(__name__)
User = get_user_model()


class KeycloakSync:
    """
    Syncs data between the local application and Keycloak.
    This class manages interactions with Keycloak, including fetching and creating clients,
    resources, roles, permissions, scopes, policies, and users.
    """

    def __post_init__(self):
        """
        Initializes the Keycloak client ID and sets up various maps for handling different entities
        and their creation. It ensures that the Keycloak client exists and initializes necessary
        components like the generator and formatter.
        """
        # Get the Keycloak client ID from the environment or create it if it doesn't exist
        self.kc_client_id = self._get_obj_by_kc_key(
            kc_admin.get_clients,
            KC_UTILS_KC_CLIENT_ID,
            "clientId",
            "id",
        )
        if not self.kc_client_id:
            logger.info(
                f"{KC_UTILS_KC_CLIENT_ID} client does not exist in current realm, creating...",
            )
            self.kc_client_id = KeycloakBase(
                kc_admin.connection.realm_name,
            ).create_client(KC_UTILS_KC_CLIENT_ID, "private")

        # Initialize the generator and formatter
        self._generator = self._create_generator()
        self.formatter = self._Formatter(self)

        # Mapping for fetching different Keycloak entities
        self.entity_fetchers_map = {
            "resource": kc_admin.get_client_authz_resources,
            "scope": kc_admin.get_client_authz_scopes,
            "permission": kc_admin.get_client_authz_permissions,
            "role": kc_admin.get_client_roles,
            "policy": kc_admin.get_client_authz_policies,
            "user": kc_admin.get_users,
        }

        # Mapping for creating different Keycloak entities
        self.entity_creators_map = {
            "resource": lambda json: kc_admin.create_client_authz_resource(
                self.kc_client_id,
                json,
                skip_exists=True,
            ),
            "scope": lambda json: kc_admin.create_client_authz_scopes(
                self.kc_client_id,
                json,
            ),
            "permission": lambda json: kc_admin.create_client_authz_scope_permission(
                json,
                self.kc_client_id,
            ),
            "role": lambda json: kc_admin.create_client_role(
                self.kc_client_id,
                json,
                skip_exists=True,
            ),
            "policy": lambda json: kc_admin.create_client_authz_role_based_policy(
                self.kc_client_id,
                json,
                skip_exists=True,
            ),
            "user": lambda json: kc_admin.create_user(json),
        }

    class _Formatter:
        """
        Internal class to handle formatting strategies for resources and scopes.
        """

        def __init__(self, outer_instance: "KeycloakSync"):
            self.outer_instance = outer_instance

        def format_resource(self, model_name: str) -> Dict[str, Any]:
            """
            Returns a JSON structured Resource as (name, display_name).
            """
            model_name = model_name.title()
            app_label, model = model_name.split(".")
            formatted_resource = f"{app_label}.{model}"
            formatted_resource_display = f"{app_label}.{model}"
            resource_dict = {
                "name": formatted_resource,
                "displayName": formatted_resource_display,
            }
            return resource_dict

        def format_scope(self, perm: Permission) -> Dict[str, Any]:
            """
            Returns a JSON structured Scope as (name, display_name).
            """
            model = perm.content_type.model
            app_label = perm.content_type.app_label
            try:
                action = perm.name.split(" ")[1]
            except IndexError:
                action = perm.name.split("_")[1]

            formatted_auth_scope = f"{app_label}.{model}.{action}_{model}"
            formatted_auth_scope_display = (
                f"{formatted_auth_scope}.can_{action}_{model}"
            )
            scope_dict = {
                "name": formatted_auth_scope,
                "displayName": formatted_auth_scope_display,
            }
            return scope_dict

        def format_permission(self, perm: Permission) -> Dict[str, Any]:
            """
            Returns a JSON structured Permission as (name, description, scopes).
            """
            self.outer_instance: KeycloakPermission
            formatted_auth_scope, formatted_auth_scope_display = self.format_scope(
                perm,
            ).values()
            formatted_auth_permission = f"{formatted_auth_scope}.perm"
            formatted_auth_perm_desc = formatted_auth_scope_display
            permission_dict = {
                "name": formatted_auth_permission,
                "description": formatted_auth_perm_desc,
                "scopes": [
                    self.outer_instance.current_scope_id,
                ],
                "type": "scope",
            }
            return permission_dict

        def format_role(self, group: Group) -> Dict[str, Any]:
            name = group.name
            description = f"{name}Role"
            role_dict = {"name": name, "description": description}
            return role_dict

        def format_policy(self, group: Group) -> Dict[str, Any]:
            self.outer_instance: KeycloakRole
            name = f"{group.name}Policy"
            description = f"{name}Policy"
            policy_dict = {
                "name": name,
                "description": description,
                "roles": [{"id": self.outer_instance.current_role}],
                "type": "role",
            }
            return policy_dict

        def format_user(self, user: User) -> Dict[str, Any]:
            def credential_representation_from_hash(
                hash_: str,
                temporary: bool = False,
            ) -> List:
                """
                Convert django password to keycloak supported credentials format
                """
                try:
                    algorithm, hashIterations, salt, hashedSaltedValue = hash_.split(
                        "$",
                    )
                except ValueError:
                    logger.warning(
                        f"user {user.username} password is incompatible and is not migrated",
                    )
                    return []
                return [
                    {
                        "type": "password",
                        "hashedSaltedValue": hashedSaltedValue,
                        "algorithm": algorithm.replace("_", "-"),
                        "hashIterations": int(hashIterations),
                        "salt": base64.b64encode(salt.encode()).decode("ascii").strip(),
                        "temporary": temporary,
                        "userLabel": "Password",
                    },
                ]

            user_dict = {
                "id": user.id,
                "username": user.username.lower(),
                "firstName": user.first_name,
                "lastName": user.last_name,
                "email": user.email,
                "enabled": user.is_active,
                "emailVerified": user.is_active,
                "credentials": credential_representation_from_hash(user.password),
            }
            return user_dict

        def format_realm(self, realm_name: str) -> Dict[str, Any]:
            realm_dict = {
                "id": realm_name,
                "realm": realm_name,
                "enabled": True,
                "displayName": realm_name,
                "sslRequired": "external",
                "loginTheme": "ottu-light",
                "accountTheme": "ottu-light",
                "adminTheme": "ottu-light",
                "accessTokenLifespan": 900,
                "attributes": {"attributesEnabled": "true"},
            }
            return realm_dict

        def format_protocol_mapper(self, client_name: str) -> Dict[str, Any]:
            audience_mapper_dict = {
                "name": client_name,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "claim.name": client_name,
                    "id.token.claim": "true",
                    "included.client.audience": client_name,
                    "included.custom.audience": "",
                    "access.token.claim": "true",
                    "userinfo.token.claim": "true",
                },
            }

            user_attr_mapper = {
                "name": client_name,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-attribute-mapper",
                "config": {
                    "claim.name": client_name,
                    "id.token.claim": "true",
                    "access.token.claim": "true",
                    "lightweight.claim": "true",
                    "userinfo.token.claim": "true",
                    "introspection.token.claim": "true",
                    "user.attribute": client_name,
                    "jsonType.label": "String",
                },
            }

            mapper_creators = {
                "audience": audience_mapper_dict,
                "user_attribute": user_attr_mapper,
            }
            return mapper_creators

        def format_client_scope(self, client_scope_name: str) -> Dict[str, Any]:
            client_scope_dict = {
                "name": client_scope_name,
                "description": client_scope_name,
                "type": "none" if client_scope_name != "timezone" else "default",
                "protocol": "openid-connect",
                "attributes": {
                    "display.on.consent.screen": "true",
                    "consent.screen.text": "",
                    "include.in.token.scope": False,
                    "gui.order": "",
                },
            }
            return client_scope_dict

        def format_client(self, client_data: List[str]) -> Dict[str, Any]:
            self.outer_instance: KeycloakBase
            client_name, client_type = client_data
            base_payload = {
                "clientId": client_name,
                "name": client_name,
                "description": client_name,
                "enabled": True,
                "clientAuthenticatorType": "client-secret",
                "redirectUris": [f"https://{self.outer_instance.realm_name}/*"],
                "webOrigins": ["*"],
                "protocol": "openid-connect",
                "fullScopeAllowed": True,
                "attributes": {
                    "login_theme": "ottu-light",
                },
            }

            def public_client_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
                payload |= {"publicClient": True}
                return payload

            def private_client_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
                payload |= {
                    "publicClient": False,
                    "standardFlowEnabled": True,
                    "implicitFlowEnabled": False,
                    "directAccessGrantsEnabled": True,
                    "protocol": "openid-connect",
                    "fullScopeAllowed": True,
                    "authorizationServicesEnabled": True,
                    "serviceAccountsEnabled": True,
                    "authorizationSettings": {
                        "allowRemoteResourceManagement": True,
                        "decisionStrategy": "AFFIRMATIVE",
                        "policyEnforcementMode": "ENFORCING",
                    },
                }
                return payload

            client_type_mapper = {
                "public": public_client_payload,
                "private": private_client_payload,
            }

            return client_type_mapper[client_type](base_payload)

    def _jsonify(self, _object=None, strategy=None) -> Dict[str, Any]:
        """
        Converts a given object into a JSON-friendly dictionary using a specific formatting strategy.

        This method selects a formatting strategy based on the `strategy` argument and applies it to
        the provided `_object`. The available strategies are "resource", "scope", "permission", "role",
        "policy", "user", "realm", "protocol_mapper", "client_scope", and "client".

        :param _object: The object to be formatted. Must be non-empty.
        :param strategy: The strategy to use for formatting the object. Should be one of the available strategies.
        :return: A dictionary representing the formatted object in a JSON-friendly format.
        :raises ValueError: If the object is empty or if an invalid strategy is provided.
        """
        if not _object:
            raise ValueError("Object cannot be empty.")

        strategy_map = {
            "resource": self.formatter.format_resource,
            "scope": self.formatter.format_scope,
            "permission": self.formatter.format_permission,
            "role": self.formatter.format_role,
            "policy": self.formatter.format_policy,
            "user": self.formatter.format_user,
            "realm": self.formatter.format_realm,
            "protocol_mapper": self.formatter.format_protocol_mapper,
            "client_scope": self.formatter.format_client_scope,
            "client": self.formatter.format_client,
        }

        if strategy not in strategy_map:
            raise ValueError(
                f"Invalid strategy: {strategy}. please select one of {strategy_map.keys()}",
            )

        return strategy_map[strategy](_object)

    def _get_obj_by_kc_key(
        self,
        kc_admin_objs_getter: Callable[[Optional[str]], List[Dict[str, Any]]],
        obj_value: Any,
        fetch_key: str,
        return_key: Optional[str] = None,
        use_admin: bool = False,
    ) -> Optional[Any]:
        """
        Fetches an object from Keycloak by its unique key.

        This method fetches a list of objects from Keycloak (either using admin privileges or not),
        and then searches for an object that matches the provided `fetch_key` and `obj_value`.
        If a match is found, the specified `return_key` is returned from the matched object.

        :param kc_admin_objs_getter: The callable that fetches Keycloak objects. It takes an optional argument for the client ID.
        :param obj_value: The value to match against the `fetch_key` in the objects.
        :param fetch_key: The key used to match the `obj_value` in the objects.
        :param return_key: The key from the object to return. If None, the whole object is returned.
        :param use_admin: Whether to use admin privileges to fetch the objects. Defaults to False.
        :return: The value of `return_key` from the matched object, or None if no match is found.
        """
        objects = (
            kc_admin_objs_getter(self.kc_client_id)
            if use_admin
            else kc_admin_objs_getter()
        )
        obj = next(
            (obj for obj in objects if obj.get(fetch_key) == obj_value),
            None,
        )
        return obj[return_key] if return_key and obj else obj

    def _get_kc_entity_by_name(
        self,
        entity_name: str,
        entity_type: str,
    ) -> Optional[Dict]:
        """
        Fetches an authorization entity (resource, scope, or permission) by its name from Keycloak.

        This method uses a specific entity fetcher function to retrieve the entity from Keycloak by its
        name. The entity type determines which fetcher function is used.

        :param entity_type: The type of entity to fetch ('resources', 'scopes', or 'permissions').
        :param entity_name: The name of the entity to search for.
        :return: The matching entity if found, otherwise None.
        :raises ValueError: If an invalid entity type is provided.
        """
        if entity_type not in self.entity_fetchers_map:
            raise ValueError(
                f"Invalid entity type: {entity_type}. Must be one of {', '.join(self.entity_fetchers_map.keys())}.",
            )
        fetcher_func = self.entity_fetchers_map[entity_type]
        key, use_admin = (
            ("username", False) if entity_type == "user" else ("name", True)
        )

        obj = self._get_obj_by_kc_key(
            fetcher_func,
            entity_name,
            key,
            use_admin=use_admin,
        )
        return obj

    def __create_kc_entity(self, json: Dict, entity_type: str) -> Optional[Dict]:
        """
        Creates an authorization entity (resource, scope, or permission) in Keycloak.

        This method takes a JSON payload with entity details and creates the specified entity type
        (e.g., resource, scope, or permission) in Keycloak.

        :param json: The JSON payload with the entity details.
        :param entity_type: The type of entity to create ('resource', 'scope', 'permission').
        :return: The created entity as a dictionary.
        :raises ValueError: If the entity type is invalid.
        """
        if entity_type not in self.entity_creators_map:
            raise ValueError(
                f"Invalid entity type: {entity_type}. Must be one of {', '.join(self.entity_creators_map.keys())}.",
            )

        return self.entity_creators_map[entity_type](json)

    def _get_or_create_kc_entity(
        self,
        json: Dict,
        entity_type: str,
        key="name",
    ) -> Optional[Dict]:
        """
        Fetches an entity by its name or creates it if it does not exist.

        This method checks if an entity with the given name already exists in Keycloak. If not, it creates
        the entity using the provided JSON payload. The entity is returned either way.

        :param json: The JSON payload with the entity details.
        :param entity_type: The type of entity to fetch or create.
        :param key: The key used to uniquely identify the entity by its name (default is "name").
        :return: The fetched or newly created entity as a dictionary.
        """
        entity_name = json[key]
        if (
            entity := self._get_kc_entity_by_name(entity_name, entity_type=entity_type)
        ) is not None:
            logger.info(f'{entity_type} {entity.get(key, "")} already exists.')

        else:
            entity = cast(Dict, self.__create_kc_entity(json, entity_type))
            logger.info(f"created {entity_type} {entity_name}.")

        if isinstance(entity, str):
            entity = self._get_kc_entity_by_name(entity_name, entity_type=entity_type)
        return entity

    def _get_next_object(self) -> Optional[Permission | Group | User]:
        """
        Fetches the next object (permission, group, or user) from the generator.

        This method retrieves the next object from the generator. It returns None if no more objects are available.

        :return: The next object (permission, group, or user) or None if the generator is exhausted.
        """
        try:
            return next(self._generator)
        except StopIteration:
            return None

    def _create_generator(self) -> Generator[Permission, None, None]:
        """
        Creates a generator to yield permissions.

        This method generates a sequence of permissions.

        :return: A generator that yields permissions.
        """
        # Implementation goes here...

    @abstractmethod
    def run_routine(self) -> None:
        """
        Executes the routine for processing authorization entities.

        This is an abstract method that must be implemented in a subclass. It is meant to handle
        the processing of authorization entities according to the specific routine.

        :raises NotImplementedError: This method must be implemented in a subclass.
        """
        raise NotImplementedError

    @classmethod
    def store_kc_id(cls, func: Callable) -> Callable:
        """
        A decorator to store the Keycloak ID after creating or updating an entity.

        This method wraps a function to store the Keycloak ID returned by the function. The `kc_id` is
        stored in the instance, and if the instance has a `save` method, it is called to save the instance.

        :param func: The function to wrap.
        :return: The wrapped function.
        """

        @wraps(func)
        def wrapper(*args, **kwargs) -> object:
            instance = args[1]
            kc_obj = func(*args, **kwargs)
            kc_id = kc_obj["id"]
            setattr(instance, "kc_id", kc_id)
            if hasattr(instance, "save"):
                instance.save()
            return kc_obj

        return wrapper


@dataclass
class KeycloakPermission(KeycloakSync):
    """
    A class to handle the synchronization of Keycloak permissions.

    This class is responsible for managing and migrating permissions from Django models
    to Keycloak, including creating resources, scopes, and permissions in Keycloak based
    on the defined desired models.

    Attributes:
        desired_models_perms_map (Dict[str, List]): A dictionary mapping model names to permission codenames.
        _permission_generator (Generator[object, None, None]): A generator for fetching permissions.
        current_resource_id (str): The ID of the current resource in Keycloak.
        current_scope_id (str): The ID of the current scope in Keycloak.
    """

    desired_models_perms_map: Dict[str, List] = field(default_factory=dict)
    _permission_generator: Generator[object, None, None] = field(init=False, repr=False)
    current_resource_id: str = None
    current_scope_id: str = None

    def __post_init__(self):
        """
        Post-initialization process for KeycloakPermission.

        This method validates the desired models-permissions mapping and initializes
        the permission generator for the object.
        """
        super().__post_init__()
        self._validate_desired_models_perms_map()

    def _validate_desired_models_perms_map(self) -> None:
        """
        Validates the desired models-permissions map, ensuring each model has associated permissions.

        If no desired models are specified, the method will populate the map with permissions
        from the Django database.
        """
        if self.desired_models_perms_map:
            return

        for perm in Permission.objects.all():
            content_type = perm.content_type
            perm_key = f"{content_type.app_label}.{content_type.model}"
            base_perm = perm.codename.split("_")[0]
            if perm_key not in self.desired_models_perms_map:
                self.desired_models_perms_map[perm_key] = []
            self.desired_models_perms_map[perm_key].append(base_perm)

    def _is_valid_model(self, model_name: str) -> bool:
        """
        Validates whether a given model name is valid and associated with permissions.

        Args:
            model_name (str): The model name in the format 'app_label.ModelName'.

        Returns:
            bool: True if the model exists and has associated permissions, False otherwise.
        """
        try:
            app_label, model = model_name.split(".")
            apps.get_model(app_label, model)

            if not Permission.objects.filter(content_type__model=model):
                logger.warning(
                    f"Model '{model_name}' does not have associated permissions.",
                )
                return False

            return True

        except ValueError:
            logger.warning(
                f"Value Error: Model {model_name} string must be in the format "
                "'app_label.ModelName'.",
            )
            return False

        except LookupError:
            logger.warning(f"Lookup Error: Model '{model_name}' could not be found.")
            return False

    def _model_registered_perms_generator(
        self,
        model_name: str,
        django_perms: QuerySet,
    ) -> Optional[QuerySet]:
        """
        Generates a filtered queryset of permissions for a given model, based on the registered permissions.

        Args:
            model_name (str): The model name in the format 'app_label.ModelName'.
            django_perms (QuerySet): A queryset of permissions.

        Returns:
            Optional[QuerySet]: The filtered queryset of permissions, or None if no matching permissions exist.
        """
        from django.contrib.contenttypes.models import ContentType

        registered_perms = self.desired_models_perms_map[model_name]
        query = Q()
        try:
            app_label, model_name = model_name.split(".")

            content_type = ContentType.objects.get(
                app_label=app_label,
                model=model_name.lower(),
            )
        except ContentType.DoesNotExist:
            logger.warning(f"Content type for {model_name} does not exist.")
            return None

        for registered_perm in registered_perms:
            query |= Q(content_type=content_type, codename__startswith=registered_perm)

        perms = django_perms.filter(query)
        if not perms:
            logger.warning(
                f"{model_name} does not have any of {registered_perms} permissions.",
            )

        return perms

    def _create_generator(self) -> Generator[Permission, None, None]:
        """
        Creates a generator that fetches the desired permissions for each model.

        This method will validate the model, check for associated permissions,
        and yield the filtered permissions for valid models.

        Yields:
            Permission: The next permission object for a valid model.
        """
        for model_name in self.desired_models_perms_map:
            if not self._is_valid_model(model_name):
                logger.warning(
                    f"Model {model_name} permissions will not be migrated to Keycloak",
                )
                continue

            app_label, model = model_name.split(".")
            permissions = Permission.objects.filter(content_type__model=model)

            self.create_kc_resource(model_name)
            filtered_permissions = self._model_registered_perms_generator(
                model_name,
                permissions,
            )
            yield from filtered_permissions

    def create_kc_resource(self, model: str) -> None:
        """
        Creates a Keycloak resource based on the model name.

        Args:
            model (str): The model name in the format 'app_label.ModelName'.
        """
        json_resource = self._jsonify(model, strategy="resource")
        resource = self._get_or_create_kc_entity(json_resource, entity_type="resource")
        self.current_resource_id = resource["_id"]

    def create_kc_scope(self, permission: Permission) -> Dict[str, Any]:
        """
        Creates a Keycloak scope based on the given permission.

        Args:
            permission (Permission): The permission object to create a scope for.

        Returns:
            Dict[str, Any]: The created scope object.
        """
        json_scope = self._jsonify(permission, strategy="scope")
        scope = self._get_or_create_kc_entity(json_scope, entity_type="scope")
        self.current_scope_id = scope["id"]
        return scope

    def add_kc_scope_to_resource(self, scope: Dict[str, Any]) -> None:
        """
        Adds the created scope to the corresponding Keycloak resource.

        Args:
            scope (Dict[str, Any]): The scope object to be added to the resource.
        """
        resource = kc_admin.get_client_authz_resource(
            self.kc_client_id,
            self.current_resource_id,
        )
        try:
            resource["scopes"] = resource.get("scopes", [])
            if any(
                resource_scope["name"] == scope["name"]
                for resource_scope in resource["scopes"]
            ):
                logger.info(
                    f'Scope {scope["name"]} already exists in resource {resource["name"]}',
                )
                return

            resource["scopes"].append(scope)
            kc_admin.update_client_authz_resource(
                self.kc_client_id,
                self.current_resource_id,
                resource,
            )

            logger.info(f'Added scope {scope["name"]} to resource {resource["name"]}')

        except Exception as e:
            logger.error(f"An error occurred while creating authz scope {e}")
            raise e

    @KeycloakSync.store_kc_id
    def create_kc_permission(self, permission: Permission) -> Dict[str, Any]:
        """
        Creates a Keycloak permission for the given permission object.

        Args:
            permission (Permission): The permission object to create a permission for.

        Returns:
            Dict[str, Any]: The created permission object.
        """
        json_perm = self._jsonify(permission, strategy="permission")
        kc_permission = self._get_or_create_kc_entity(
            json_perm,
            entity_type="permission",
        )
        return kc_permission

    def run_routine(self) -> None:
        """
        Runs the permission synchronization routine.

        The method fetches permissions from the generator and processes them by creating
        Keycloak resources, scopes, and permissions, handling errors as needed.
        """
        while True:
            permission = self._get_next_object()
            if permission is None:
                break
            try:
                scope = self.create_kc_scope(permission)
                self.add_kc_scope_to_resource(scope)
                # self.create_kc_permission(permission)
            except ValueError as ve:
                logger.error(f"Skipping invalid permission: {ve}")
                continue
            except Exception as e:
                logger.error(f"Error processing permission '{permission}': {e}")
                raise e


@dataclass
class KeycloakRole(KeycloakSync):
    current_role: str = None  # The current role ID in Keycloak
    current_policy: str = None  # The current policy ID in Keycloak

    def _create_generator(self) -> Generator[Group, None, None]:
        """
        Internal method to create a generator that fetches all Group objects from Django.
        Yields: Group objects.
        """
        groups = Group.objects.all()
        yield from groups

    @KeycloakSync.store_kc_id
    def create_role(self, group: Group) -> Dict[str, Any]:
        """
        Creates a Keycloak role based on the provided Group object.
        Args:
            group: The Group object to sync with Keycloak.
        Returns:
            The created Keycloak role as a dictionary.
        """
        json_role = self._jsonify(group, strategy="role")
        role = self._get_or_create_kc_entity(json_role, entity_type="role")
        self.current_role = role["id"]
        return role

    def get_or_create_policy(self, group: Group, role_id: str = None):
        """
        Retrieves or creates a policy based on the provided Group.
        If role_id is provided, updates the current_role.
        Args:
            group: The Group object to sync with Keycloak.
            role_id: Optional role ID to update the current role.
        Returns:
            The created or retrieved policy as a dictionary.
        """
        if role_id:
            self.current_role = role_id
        json_policy = self._jsonify(group, strategy="policy")
        policy = self._get_or_create_kc_entity(json_policy, entity_type="policy")
        return policy

    def delete_policy(self, group_name: str) -> None:
        """
        Deletes the policy associated with the given group_name from Keycloak.
        Args:
            group_name: The name of the group whose policy will be deleted.
        """
        policy = self._get_kc_entity_by_name(group_name, entity_type="policy")
        if policy is None:
            logger.warning(f"the policy {policy} does not exist in Keycloak")
            return
        policy_id = policy["id"]
        kc_admin.delete_client_authz_policy(self.kc_client_id, policy_id)

    def add_policies_to_permissions(self, group: Group) -> None:
        """
        Associates policies with permissions for the given Group.
        Args:
            group: The Group object to associate policies with permissions.
        """
        kc_perm_obj = KeycloakPermission()
        permissions = group.permissions.all()
        for permission in permissions:
            scope = kc_perm_obj.create_kc_scope(permission)
            kc_permission = kc_perm_obj.create_kc_permission(permission)

            kc_permission_id = kc_permission.pop("id")
            json_policy = self._jsonify(group, strategy="policy")
            policy = self._get_or_create_kc_entity(json_policy, entity_type="policy")
            permission_policies = (
                kc_admin.get_client_authz_permission_associated_policies(
                    self.kc_client_id,
                    kc_permission_id,
                )
            )

            if not all(policy["name"] != p["name"] for p in permission_policies):
                logger.info(
                    f'Policy {policy["name"]} already exists in permission {kc_permission["name"]}',
                )
                continue

            kc_permission["scopes"] = [scope["id"]]
            permission_policies.append(policy)
            kc_permission["policies"] = [policy["id"] for policy in permission_policies]
            kc_admin.update_client_authz_scope_permission(
                kc_permission,
                self.kc_client_id,
                kc_permission_id,
            )
            logger.info(f'Added {policy["name"]} to permission {kc_permission["name"]}')

    def run_routine(self) -> None:
        """
        Runs the routine to create roles, policies, and associate them with permissions for all Groups.
        """
        while True:
            group = self._get_next_object()
            if group is None:
                break

            try:
                self.create_role(group)
                self.get_or_create_policy(group)
                self.add_policies_to_permissions(group)
            except ValueError as ve:
                logger.error(f"Skipping invalid permission: {ve}")
                continue
            except Exception as e:
                logger.error(f"Error processing group '{group}': {e}")
                raise e


@dataclass
class KeycloakUser(KeycloakSync):
    current_user: str = None  # The current user ID in Keycloak

    def __post_init__(self):
        """
        Initializes the core client ID.
        """
        super().__post_init__()
        self.core_client_id = self._get_obj_by_kc_key(
            kc_admin.get_clients,
            "core",
            "clientId",
            "id",
        )

    def _create_generator(self) -> Generator[User, None, None]:
        """
        Internal method to create a generator that fetches all User objects from Django.
        Yields: User objects.
        """
        users = User.objects.all()
        yield from users

    @KeycloakSync.store_kc_id
    def create_user(self, user: User) -> Dict[str, Any]:
        """
        Creates a Keycloak user based on the provided User object.
        Args:
            user: The User object to sync with Keycloak.
        Returns:
            The created Keycloak user as a dictionary.
        """
        json_user = self._jsonify(user, strategy="user")
        kc_user = self._get_or_create_kc_entity(
            json_user,
            entity_type="user",
            key="username",
        )
        self.add_tz_user_attr(kc_user, user)

        self.current_user = kc_user["id"]
        return kc_user

    def add_tz_user_attr(self, kc_user: Dict, user: User) -> None:
        """
        Adds timezone attribute to the Keycloak user based on the User's timezone.
        Args:
            kc_user: The Keycloak user dictionary to update.
            user: The User object containing the timezone.
        """
        user_tz = getattr(user, "timezone", None)
        timezone = [user_tz] if user_tz else ["Asia/Kuwait"]
        kc_user |= {"attributes": {"timezone": timezone}}
        kc_admin.update_user(kc_user["id"], kc_user)

    def _add_superadmin_roles(self) -> None:
        """
        Assigns superadmin roles to the current user in Keycloak.
        """
        admin_roles = ["manage-clients", "query-users", "create-client"]
        realm_manage_client_id = self._get_obj_by_kc_key(
            kc_admin.get_clients,
            "realm-management",
            "clientId",
            "id",
        )
        if not realm_manage_client_id:
            logger.info("")
            return
        superadmin_management_roles = [
            kc_admin.get_client_role(realm_manage_client_id, role)
            for role in admin_roles
        ]
        kc_admin.assign_client_role(
            self.current_user,
            realm_manage_client_id,
            superadmin_management_roles,
        )
        superadmin_realm_role = kc_admin.get_realm_role("super_admin")
        kc_admin.assign_realm_roles(self.current_user, [superadmin_realm_role])

        superadmin_client_role = kc_admin.get_client_role(
            self.core_client_id,
            "super_admin",
        )
        kc_admin.assign_client_role(
            self.current_user,
            self.core_client_id,
            [superadmin_client_role],
        )

    def assign_user_roles(self, user: User) -> None:
        """
        Assigns roles to the user based on their Group membership.
        Args:
            user: The User object to assign roles to.
        """
        groups = user.groups.all()
        roles = []
        for group in groups:
            json_role = self._jsonify(group, strategy="role")
            role = self._get_or_create_kc_entity(json_role, entity_type="role")
            roles.append(role)
        kc_admin.assign_client_role(self.current_user, self.kc_client_id, roles)
        if user.is_superuser:
            self._add_superadmin_roles()

    def run_routine(self) -> None:
        """
        Runs the routine to create users and assign them roles.
        """
        while True:
            user = self._get_next_object()
            if user is None:
                break

            try:
                self.create_user(user)
                self.assign_user_roles(user)
            except ValueError as ve:
                logger.error(f"Skipping user: {ve}")
                continue
            except Exception as e:
                logger.error(f"Error processing user '{user}': {e}")
                continue


@dataclass
class KeycloakBase(KeycloakSync):
    """
    This class handles the synchronization and management of Keycloak realms, clients,
    and associated configuration, including the creation of realms, clients, and roles.
    It validates client configurations, creates client scopes, and assigns protocol mappers.

    Attributes:
        realm_name (str): The name of the Keycloak realm to be created or managed.
        clients (Dict[str, List]): Dictionary containing client types ("private" and "public") with client names.

    Methods:
        run_routine() -> bool:
            Runs the entire synchronization routine, including realm and client creation, and superadmin role setup.
    """

    realm_name: str
    clients: Dict[str, List] = field(default_factory=dict)

    def __post_init__(self):
        """
        Post-initialization method that initializes the formatter and validates the client configurations.
        """
        self.formatter = self._Formatter(self)
        self._validate_clients()

    def _validate_clients(self) -> None:
        """
        Validates and processes client lists to ensure there are no duplicates between "private" and "public" clients.
        Logs warnings for duplicate clients and ensures unique client names for both categories.

        Logs:
            Warning: If duplicate clients are found and ignored.
        """
        for clients_type in ["private", "public"]:
            clients = self.clients.get(f"{clients_type}", {}) or {}
            base_clients_dict = {
                "private": {"core"},
                "public": {"frontend"},
            }
            base_clients = base_clients_dict[clients_type]
            filtered_clients = set(clients)

            duplicates = filtered_clients.intersection(base_clients)
            if duplicates:
                logger.warning(
                    f"The following clients are duplicates and will be ignored: {', '.join(duplicates)}",
                )

            self.clients[clients_type] = list(base_clients.union(filtered_clients))

    def create_realm(self) -> None:
        """
        Creates a Keycloak realm using the provided realm name and initializes configuration settings.

        Args:
            None

        Logs:
            Info: Logs success after realm creation.
            Error: Logs if there is a failure in realm creation.
        """
        json_realm = self._jsonify(self.realm_name, strategy="realm")
        kc_admin.create_realm(json_realm, skip_exists=True)
        logger.info(f"Created realm {self.realm_name} successfully.")

        def update_up_config() -> None:
            """Updates the realm's up-config to enable unmanaged attribute policy."""
            up_config = kc_admin.get_realm_upconfig(self.realm_name)
            up_config |= {"unmanagedAttributePolicy": "ENABLED"}
            kc_admin.update_realm_upconfig(self.realm_name, up_config)

        update_up_config()
        kc_admin.connection.realm_name = self.realm_name

        client_scope_id = self.create_client_scope("timezone")
        self.create_client_protocol_mapper(
            "timezone",
            client_scope_id,
            mapper_type="user_attribute",
        )

    def create_client_protocol_mapper(
        self,
        client_name: str,
        client_scope_id: str,
        mapper_type: str = "audience",
    ):
        """
        Creates a protocol mapper for a client using the specified mapper type (e.g., "audience" or "user_attribute").

        Args:
            client_name (str): The name of the client to create the protocol mapper for.
            client_scope_id (str): The ID of the client scope associated with the mapper.
            mapper_type (str): The type of the protocol mapper. Default is "audience".

        Logs:
            Info: Logs success after creating the protocol mapper.
        """
        protocol_mappers = self._jsonify(client_name, "protocol_mapper")
        kc_admin.create_client_scope_mapper(
            client_scope_id,
            protocol_mappers[mapper_type],
        )
        logger.info(f"Created {mapper_type} protocol mapper.")

    def create_client_scope(self, client_name: str) -> str:
        """
        Creates a client scope for a given client name.

        Args:
            client_name (str): The name of the client for which the client scope will be created.

        Returns:
            str: The ID of the created client scope.

        Logs:
            Info: Logs success after creating the client scope.
        """
        payload = self._jsonify(client_name, "client_scope")
        client_scope = kc_admin.create_client_scope(payload, skip_exists=True)
        logger.info(f"Created client scope {client_name} successfully.")
        return client_scope

    def add_client_scope_to_client(
        self,
        client_id: str,
        client_scope_name: str = "timezone",
    ) -> None:
        """
        Adds a client scope (e.g., "timezone") to a client.

        Args:
            client_id (str): The ID of the client to which the scope will be added.
            client_scope_name (str): The name of the client scope to be added. Default is "timezone".

        Logs:
            Info: Logs success after adding the client scope to the client.
        """
        client_scope_id = self._get_obj_by_kc_key(
            kc_admin.get_client_scopes,
            client_scope_name,
            "name",
            "id",
        )
        payload = {
            "realm": kc_admin.connection.realm_name,
            "client": client_id,
            "clientScopeId": client_scope_id,
        }
        kc_admin.add_client_default_client_scope(client_id, client_scope_id, payload)
        logger.info(f"Added client scope {client_scope_name} to client {client_id}.")

    def create_client(self, client_name: str, client_type: str = "private") -> str:
        """
        Creates a Keycloak client of the specified type (private or public).

        Args:
            client_name (str): The name of the client to be created.
            client_type (str): The type of client to be created. Default is "private".

        Returns:
            str: The ID of the created client.

        Logs:
            Info: Logs success after client creation.
        """
        client_payload = self._jsonify([client_name, client_type], "client")
        client_id = kc_admin.create_client(client_payload, skip_exists=True)

        def update_resource_server() -> None:
            resource_server = kc_admin.get_client_resource_server(client_id)
            resource_server["decisionStrategy"] = "UNANIMOUS"
            kc_admin.update_client_resource_server(client_id, resource_server)

        if client_type == "private":
            update_resource_server()

        self.add_client_scope_to_client(client_id, "timezone")

        prefixed_client_name = f"{client_name}-service"
        client_scope_id = self.create_client_scope(prefixed_client_name)
        self.create_client_protocol_mapper(client_name, client_scope_id)
        self.add_client_scope_to_client(client_id, prefixed_client_name)

        if client_name == "core":
            super_admin_role = {"name": "super_admin", "description": "super_adminRole"}
            kc_admin.create_client_role(client_id, super_admin_role, skip_exists=True)
            logger.info("Created super_admin client role for core.")

        return client_id

    def create_superadmin_role(self) -> None:
        """
        Creates a superadmin role in the Keycloak realm.

        Args:
            None

        Logs:
            Info: Logs success after creating the superadmin role.
        """
        role_representation = {
            "name": "super_admin",
            "description": "super admin",
        }
        kc_admin.create_realm_role(role_representation, skip_exists=True)
        logger.info("Created super_admin role.")

    def run_routine(self) -> bool:
        """
        Runs the full synchronization routine, including realm creation, client creation,
        role creation, and the addition of required client scopes and protocol mappers.

        Args:
            None

        Returns:
            bool: Returns True if the routine completes successfully, False otherwise.

        Logs:
            Info: Logs success after completing the routine.
            Error: Logs any errors encountered during the execution of the routine.
        """
        try:
            self.create_realm()  # Create the realm
            for client, client_type in chain.from_iterable(
                ((client, client_type) for client in clients)
                for client_type, clients in self.clients.items()
            ):
                self.create_client(client, client_type=client_type)
            self.create_superadmin_role()
        except ValueError as ve:
            logger.error(f"Value Error: {ve}")
        except Exception as e:
            logger.error(f"Error: {e}")
            raise e
        return True
