"""Keycloak Admin REST API client."""

from plone import api

import logging
import requests


logger = logging.getLogger(__name__)

# Default lifespan for email links (24 hours in seconds)
DEFAULT_EMAIL_LINK_LIFESPAN = 86400


class KeycloakAdminClient:
    """Client for Keycloak Admin REST API operations."""

    def __init__(self, server_url, realm, client_id, client_secret):
        """Initialize the Keycloak admin client.

        Args:
            server_url: Base URL of the Keycloak server
                (e.g., 'https://keycloak.example.com')
            realm: The realm to manage users in
            client_id: Client ID for admin access
                (typically 'admin-cli' or a service account)
            client_secret: Client secret for authentication
        """
        self.server_url = server_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self._access_token = None
        self._session = requests.Session()

    def _get_token_url(self):
        """Get the token endpoint URL.

        Returns:
            Token endpoint URL string.
        """
        return f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/token"

    def _get_admin_url(self):
        """Get the admin API base URL for the realm.

        Returns:
            Admin API base URL string.
        """
        return f"{self.server_url}/admin/realms/{self.realm}"

    def _authenticate(self):
        """Authenticate with Keycloak and get an access token.

        Returns:
            Access token string.

        Raises:
            KeycloakAuthenticationError: If authentication fails.
        """
        token_url = self._get_token_url()
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        try:
            response = self._session.post(token_url, data=data)
            response.raise_for_status()
            token_data = response.json()
            self._access_token = token_data["access_token"]
            return self._access_token
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to authenticate with Keycloak: {e}")
            raise KeycloakAuthenticationError(f"Authentication failed: {e}") from e

    def _get_headers(self):
        """Get headers with authentication for API requests.

        Returns:
            Dict of HTTP headers.
        """
        if not self._access_token:
            self._authenticate()
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
        }

    def _make_request(self, method, url, **kwargs):
        """Make an authenticated request to Keycloak, handling token refresh.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            url: Full URL for the request
            **kwargs: Additional arguments for requests

        Returns:
            Response object.
        """
        headers = kwargs.pop("headers", {})
        headers.update(self._get_headers())
        logger.info(f"Making {method} request to {url}")
        response = self._session.request(method, url, headers=headers, **kwargs)

        # If token expired, refresh and retry once
        if response.status_code == 401:
            self._access_token = None
            headers.update(self._get_headers())
            response = self._session.request(method, url, headers=headers, **kwargs)

        return response

    def create_user(
        self,
        username,
        email,
        first_name="",
        last_name="",
        enabled=True,
        email_verified=False,
        attributes=None,
    ):
        """Create a new user in Keycloak.

        Args:
            username: Username for the new user.
            email: Email address for the new user.
            first_name: User's first name.
            last_name: User's last name.
            enabled: Whether the user account is enabled.
            email_verified: Whether the email is already verified.
            attributes: Additional custom attributes.

        Returns:
            The ID of the created user.

        Raises:
            KeycloakUserCreationError: If user creation fails.
            KeycloakUserExistsError: If user already exists.
        """
        url = f"{self._get_admin_url()}/users"

        user_data = {
            "username": username,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": enabled,
            "emailVerified": email_verified,
        }

        if attributes:
            user_data["attributes"] = attributes

        try:
            response = self._make_request("POST", url, json=user_data)

            if response.status_code == 201:
                # User created - extract ID from Location header
                location = response.headers.get("Location", "")
                user_id = location.rsplit("/", 1)[-1] if location else None
                if user_id:
                    logger.info(f"Created Keycloak user {username} with ID {user_id}")
                    return user_id
                # Fallback: get user by username
                return self.get_user_id_by_username(username)

            elif response.status_code == 409:
                # User already exists
                logger.warning(f"User {username} already exists in Keycloak")
                raise KeycloakUserExistsError(f"User {username} already exists")

            else:
                error_msg = response.json().get("errorMessage", response.text)
                logger.error(f"Failed to create user {username}: {error_msg}")
                raise KeycloakUserCreationError(f"Failed to create user: {error_msg}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed when creating user {username}: {e}")
            raise KeycloakUserCreationError(f"Request failed: {e}") from e

    def get_user(self, username, attr="username"):
        """Get a user by their username or email.

        Args:
            username: The username or value to search for.
            attr: The attribute to search by ('username' or 'email').

        Returns:
            User dict if found, None otherwise.
        """
        url = f"{self._get_admin_url()}/users"
        params = {attr: username, "exact": "true"}

        try:
            response = self._make_request("GET", url, params=params)
            response.raise_for_status()
            users = response.json()
            if users:
                return users[0]
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user ID for {username}: {e}")
            return None

    def _get_user_id(self, value, attr="username"):
        """Get a user's ID by a specific attribute.

        Args:
            value: The value to search for.
            attr: The attribute to search by ('username' or 'email').

        Returns:
            User ID if found, None otherwise.
        """
        user = self.get_user(value, attr=attr)
        return user["id"] if user else None

    def get_user_id_by_username(self, username):
        """Get a user's ID by their username.

        Args:
            username: The username to search for.

        Returns:
            User ID if found, None otherwise.
        """
        return self._get_user_id(username, attr="username")

    def get_user_id_by_email(self, email):
        """Get a user's ID by their email.

        Args:
            email: The email to search for.

        Returns:
            User ID if found, None otherwise.
        """
        return self._get_user_id(email, attr="email")

    def _build_email_params(self, lifespan, redirect_uri=None, client_id=None):
        """Build common parameters for email-related API calls.

        Args:
            lifespan: How long the link is valid in seconds.
            redirect_uri: Optional URI to redirect to after completing actions.
            client_id: Optional client ID for the redirect.

        Returns:
            Dict of parameters for the API request.
        """
        params = {"lifespan": lifespan}
        if redirect_uri:
            params["redirect_uri"] = redirect_uri
        if client_id:
            params["client_id"] = client_id
        return params

    def _send_user_email(self, url, params, email_type, user_id, json_body=None):
        """Send an email to a user via Keycloak API.

        Args:
            url: The API endpoint URL.
            params: Query parameters for the request.
            email_type: Description of email type (for logging).
            user_id: The Keycloak user ID (for logging).
            json_body: Optional JSON body for the request.

        Returns:
            True if email was sent successfully.

        Raises:
            KeycloakError: If sending the email fails.
        """
        try:
            response = self._make_request("PUT", url, params=params, json=json_body)

            if response.status_code == 204:
                logger.info(f"Sent {email_type} to user {user_id}")
                return True
            else:
                error_msg = response.text
                logger.error(
                    f"Failed to send {email_type} to user {user_id}: {error_msg}"
                )
                raise KeycloakError(f"Failed to send {email_type}: {error_msg}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed when sending {email_type}: {e}")
            raise KeycloakError(f"Request failed: {e}") from e

    def send_execute_actions_email(
        self,
        user_id,
        actions,
        lifespan=DEFAULT_EMAIL_LINK_LIFESPAN,
        redirect_uri=None,
        client_id=None,
    ):
        """Send an execute actions email to a user.

        This sends an email with a link that allows the user to perform
        required actions like setting a password, verifying email, or
        configuring 2FA (TOTP).

        Args:
            user_id: The Keycloak user ID.
            actions: List of required actions. Common values:
                - 'UPDATE_PASSWORD': Set/reset password
                - 'VERIFY_EMAIL': Verify email address
                - 'CONFIGURE_TOTP': Configure 2FA/TOTP
                - 'UPDATE_PROFILE': Update profile information
                - 'TERMS_AND_CONDITIONS': Accept terms
            lifespan: How long the link is valid in seconds (default 24 hours).
            redirect_uri: Optional URI to redirect to after completing actions.
            client_id: Optional client ID for the redirect.

        Returns:
            True if email was sent successfully.

        Raises:
            KeycloakError: If sending the email fails.
        """
        url = f"{self._get_admin_url()}/users/{user_id}/execute-actions-email"
        params = self._build_email_params(lifespan, redirect_uri, client_id)
        return self._send_user_email(
            url,
            params,
            f"execute actions email (actions: {actions})",
            user_id,
            json_body=actions,
        )

    def send_verify_email(
        self,
        user_id,
        redirect_uri=None,
        client_id=None,
        lifespan=DEFAULT_EMAIL_LINK_LIFESPAN,
    ):
        """Send a verification email to a user.

        Note: In Keycloak 24.x, this endpoint sends an execute-actions style email
        rather than a simple verification email.

        Args:
            user_id: The Keycloak user ID.
            redirect_uri: Optional URI to redirect to after verification.
            client_id: Optional client ID for the redirect.
            lifespan: How long the link is valid in seconds (default 24 hours).

        Returns:
            True if email was sent successfully.
        """
        url = f"{self._get_admin_url()}/users/{user_id}/send-verify-email"
        params = self._build_email_params(lifespan, redirect_uri, client_id)
        return self._send_user_email(url, params, "verification email", user_id)

    def set_user_required_actions(self, user_id, actions):
        """Set required actions for a user.

        These actions will be required when the user next logs in.

        Args:
            user_id: The Keycloak user ID.
            actions: List of required actions.

        Returns:
            True if actions were set successfully.
        """
        url = f"{self._get_admin_url()}/users/{user_id}"

        try:
            response = self._make_request("PUT", url, json={"requiredActions": actions})

            if response.status_code == 204:
                logger.info(f"Set required actions for user {user_id}: {actions}")
                return True
            else:
                error_msg = response.text
                logger.error(
                    f"Failed to set required actions for user {user_id}: {error_msg}"
                )
                return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed when setting required actions: {e}")
            return False

    def search_users(
        self,
        search=None,
        username=None,
        email=None,
        first_name=None,
        last_name=None,
        exact=False,
        first=0,
        max_results=None,
    ):
        """Search for users in Keycloak.

        Args:
            search: General search string (searches across username, firstName,
                lastName, email).
            username: Filter by username.
            email: Filter by email.
            first_name: Filter by first name.
            last_name: Filter by last name.
            exact: If True, require exact matches (default False for substring).
            first: Pagination offset (default 0).
            max_results: Maximum number of results to return.

        Returns:
            List of user dicts with keys: id, username, email, firstName,
            lastName, enabled, emailVerified, etc.
        """
        url = f"{self._get_admin_url()}/users"

        param_mapping = {
            "search": search,
            "username": username,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "first": first if first else None,
            "max": max_results,
        }
        params = {k: v for k, v in param_mapping.items() if v is not None}

        if exact:
            params["exact"] = "true"

        try:
            response = self._make_request("GET", url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to search users: {e}")
            return []

    def search_groups(self, search=None, exact=False, first=0, max_results=None):
        """Search for groups in Keycloak.

        Args:
            search: Search string to filter groups by name.
            exact: If True, require exact name match (default False for substring).
            first: Pagination offset (default 0).
            max_results: Maximum number of results to return.

        Returns:
            List of group dicts with keys: id, name, path, subGroupCount, etc.
        """
        url = f"{self._get_admin_url()}/groups"

        params = {}
        if search:
            params["search"] = search
        if exact:
            params["exact"] = "true"
        if first:
            params["first"] = first
        if max_results:
            params["max"] = max_results

        try:
            response = self._make_request("GET", url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to search groups: {e}")
            return []

    def get_group(self, group_id):
        """Get a group by its Keycloak UUID.

        Args:
            group_id: The Keycloak group UUID.

        Returns:
            Group dict if found, None otherwise.
        """
        url = f"{self._get_admin_url()}/groups/{group_id}"

        try:
            response = self._make_request("GET", url)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get group {group_id}: {e}")
            return None

    def get_group_by_name(self, group_name, exact=True):
        """Get a group by its name.

        Args:
            group_name: The group name to search for.
            exact: If True, require exact match (default True).

        Returns:
            Group dict if found, None otherwise.
        """
        groups = self.search_groups(search=group_name, exact=exact, max_results=10)
        for group in groups:
            if exact:
                if group.get("name") == group_name:
                    return group
            else:
                return group
        return None

    def get_groups_for_user(self, user_id):
        """Get the groups a user belongs to.

        Args:
            user_id: The Keycloak user UUID.

        Returns:
            List of group dicts with keys: id, name, path.
        """
        url = f"{self._get_admin_url()}/users/{user_id}/groups"

        try:
            response = self._make_request("GET", url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get groups for user {user_id}: {e}")
            return []

    def create_group(self, name):
        """Create a new group in Keycloak.

        Args:
            name: The name of the group to create.

        Returns:
            The ID of the created group, or None if creation failed.
        """
        url = f"{self._get_admin_url()}/groups"
        group_data = {"name": name}

        try:
            response = self._make_request("POST", url, json=group_data)

            if response.status_code == 201:
                # Group created - extract ID from Location header
                location = response.headers.get("Location", "")
                group_id = location.rsplit("/", 1)[-1] if location else None
                if group_id:
                    logger.info(f"Created Keycloak group {name} with ID {group_id}")
                    return group_id
                # Fallback: get group by name
                group = self.get_group_by_name(name, exact=True)
                return group["id"] if group else None

            elif response.status_code == 409:
                logger.warning(f"Group {name} already exists in Keycloak")
                group = self.get_group_by_name(name, exact=True)
                return group["id"] if group else None

            else:
                error_msg = response.text
                logger.error(f"Failed to create group {name}: {error_msg}")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed when creating group {name}: {e}")
            return None

    def delete_group(self, group_id):
        """Delete a group from Keycloak.

        Args:
            group_id: The Keycloak group UUID.

        Returns:
            True if deletion was successful, False otherwise.
        """
        url = f"{self._get_admin_url()}/groups/{group_id}"

        try:
            response = self._make_request("DELETE", url)
            if response.status_code == 204:
                logger.info(f"Deleted Keycloak group {group_id}")
                return True
            else:
                logger.error(f"Failed to delete group {group_id}: {response.text}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed when deleting group {group_id}: {e}")
            return False

    def add_user_to_group(self, user_id, group_id):
        """Add a user to a group.

        Args:
            user_id: The Keycloak user UUID.
            group_id: The Keycloak group UUID.

        Returns:
            True if user was added successfully, False otherwise.
        """
        url = f"{self._get_admin_url()}/users/{user_id}/groups/{group_id}"

        try:
            response = self._make_request("PUT", url)
            if response.status_code == 204:
                logger.info(f"Added user {user_id} to group {group_id}")
                return True
            else:
                logger.error(
                    f"Failed to add user {user_id} to group {group_id}: {response.text}"
                )
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed when adding user to group: {e}")
            return False

    def remove_user_from_group(self, user_id, group_id):
        """Remove a user from a group.

        Args:
            user_id: The Keycloak user UUID.
            group_id: The Keycloak group UUID.

        Returns:
            True if user was removed successfully, False otherwise.
        """
        url = f"{self._get_admin_url()}/users/{user_id}/groups/{group_id}"

        try:
            response = self._make_request("DELETE", url)
            if response.status_code == 204:
                logger.info(f"Removed user {user_id} from group {group_id}")
                return True
            else:
                logger.error(
                    f"Failed to remove user {user_id} from group "
                    f"{group_id}: {response.text}"
                )
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed when removing user from group: {e}")
            return False

    def get_group_members(self, group_id, first=0, max_results=None):
        """Get members of a group.

        Args:
            group_id: The Keycloak group UUID.
            first: Pagination offset (default 0).
            max_results: Maximum number of results to return.

        Returns:
            List of user dicts with keys: id, username, email, firstName,
            lastName, etc.
        """
        url = f"{self._get_admin_url()}/groups/{group_id}/members"

        params = {}
        if first:
            params["first"] = first
        if max_results:
            params["max"] = max_results

        try:
            response = self._make_request("GET", url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get members for group {group_id}: {e}")
            return []


class KeycloakError(Exception):
    """Base exception for Keycloak operations."""

    pass


class KeycloakAuthenticationError(KeycloakError):
    """Raised when authentication with Keycloak fails."""

    pass


class KeycloakUserCreationError(KeycloakError):
    """Raised when user creation fails."""

    pass


class KeycloakUserExistsError(KeycloakUserCreationError):
    """Raised when trying to create a user that already exists."""

    pass


def is_sync_enabled(property_name):
    """Check if a specific Keycloak sync feature is enabled.

    Args:
        property_name: The boolean property on the plugin to check
            (e.g., 'sync_groups', 'sync_users').

    Returns:
        True if the plugin exists, the property is True, and the
        Keycloak client is configured. False otherwise.
    """
    try:
        plugin = get_keycloak_plugin()
        if not plugin:
            return False

        if not getattr(plugin, property_name, False):
            return False

        return plugin.get_client() is not None
    except Exception:
        return False


def get_client_and_plugin(operation_name):
    """Get the Keycloak client and plugin, logging warnings if unavailable.

    Args:
        operation_name: Name of the operation (for log messages).

    Returns:
        Tuple of (client, plugin) or (None, None) if either is unavailable.
    """
    plugin = get_keycloak_plugin()
    if not plugin:
        logger.warning(f"KeycloakPlugin not found, skipping {operation_name}")
        return None, None

    client = plugin.get_client()
    if not client:
        logger.warning(f"Keycloak client not configured, skipping {operation_name}")
        return None, None

    return client, plugin


def get_keycloak_plugin():
    """Get the KeycloakPlugin instance from PAS.

    Returns:
        The KeycloakPlugin instance if found, None otherwise.
    """
    from Products.CMFCore.utils import getToolByName
    from wcs.keycloak.interfaces import IKeycloakPlugin

    try:
        portal = api.portal.get()
        if not portal:
            return None
        acl_users = getToolByName(portal, "acl_users")

        for _plugin_id, plugin in acl_users.objectItems():
            if IKeycloakPlugin.providedBy(plugin):
                return plugin

        logger.debug("No KeycloakPlugin found in acl_users")
        return None
    except Exception as e:
        logger.error(f"Error getting KeycloakPlugin: {e}")
        return None
