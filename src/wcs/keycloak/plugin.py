"""Keycloak PAS Plugin for Plone.

This module provides a PAS (Pluggable Authentication Service) plugin that
integrates with Keycloak for user management, enumeration, and properties.
"""
from AccessControl import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from BTrees.OOBTree import OOBTree
from plone import api
from plone.protect.utils import safeWrite
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserAdderPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from wcs.keycloak.client import DEFAULT_EMAIL_LINK_LIFESPAN
from wcs.keycloak.client import KeycloakAdminClient
from wcs.keycloak.client import KeycloakError
from wcs.keycloak.client import KeycloakUserExistsError
from wcs.keycloak.interfaces import IKeycloakPlugin
import logging


logger = logging.getLogger(__name__)


# Default maximum users to return when no search criteria specified
DEFAULT_MAX_USERS = 1000


def extract_user_storage_data(keycloak_user):
    """Build a user storage dict from a Keycloak user response.

    Args:
        keycloak_user: Dict from Keycloak API with user data.

    Returns:
        Dict with email, firstName, lastName for plugin storage.
    """
    return {
        'email': keycloak_user.get('email', ''),
        'firstName': keycloak_user.get('firstName', ''),
        'lastName': keycloak_user.get('lastName', ''),
    }


manage_addKeycloakPluginForm = PageTemplateFile("templates/add_keycloak_plugin", globals())


def manage_addKeycloakPlugin(
    self,
    id_,
    title='',
    server_url='',
    realm='',
    admin_client_id='',
    admin_client_secret='',
    RESPONSE=None,
):
    """Add a KeycloakPlugin to a Pluggable Auth Service.

    Args:
        self: The container (usually acl_users).
        id_: The ID for the new plugin.
        title: Optional title for the plugin.
        server_url: Keycloak server URL.
        realm: Keycloak realm name.
        admin_client_id: Admin client ID for API access.
        admin_client_secret: Admin client secret.
        RESPONSE: Optional Zope response object for redirect.
    """
    plugin = KeycloakPlugin(id_, title)
    self._setObject(plugin.getId(), plugin)

    # Set connection properties if provided
    plugin = self._getOb(plugin.getId())
    if server_url:
        plugin.server_url = server_url
    if realm:
        plugin.realm = realm
    if admin_client_id:
        plugin.admin_client_id = admin_client_id
    if admin_client_secret:
        plugin.admin_client_secret = admin_client_secret

    if RESPONSE is not None:
        RESPONSE.redirect("manage_workspace")


class KeycloakPlugin(BasePlugin):
    """PAS plugin that creates users in Keycloak.

    This plugin implements IUserAdderPlugin to intercept user creation
    and create the user in Keycloak.

    When a user is created:
    1. The user is created in Keycloak with the provided credentials
    2. An execute-actions email is sent to the user with actions based on
       the plugin configuration (password setup, email verification, 2FA)

    Minimal keycloak config:
    Have a client in Keycloak with:
    - Settings -> Service accounts roles enabled
    - Settings Client Authentification enabled (this enables the Creditals tab)
    - Service account roles: manage-users, view-user and query-users

    Attributes:
        meta_type: The Zope meta type for this plugin.
        title: The title of this plugin instance.
        server_url: Keycloak server URL.
        realm: Keycloak realm name.
        admin_client_id: Admin client ID for API access.
        admin_client_secret: Admin client secret.
        sync_groups: Whether to sync groups on user login.
        send_password_reset: Whether to send password reset email.
        send_verify_email: Whether to send email verification.
        require_totp: Whether to require 2FA setup.
        email_link_lifespan: How long email links are valid (seconds).
        redirect_uri: Redirect URI after completing Keycloak actions.
        redirect_client_id: Client ID for redirect.
    """

    meta_type = 'Keycloak Plugin'
    zmi_icon = 'fas fa-key'

    security = ClassSecurityInfo()

    # Plugin properties
    _properties = (
        {
            'id': 'title',
            'type': 'string',
            'mode': 'w',
            'label': 'Title'
        },
        {
            'id': 'server_url',
            'type': 'string',
            'mode': 'w',
            'label': 'Keycloak Server URL (e.g., https://keycloak.example.com)'
        },
        {
            'id': 'realm',
            'type': 'string',
            'mode': 'w',
            'label': 'Keycloak Realm'
        },
        {
            'id': 'admin_client_id',
            'type': 'string',
            'mode': 'w',
            'label': 'Admin Client ID (service account with manage-users permission)'
        },
        {
            'id': 'admin_client_secret',
            'type': 'string',
            'mode': 'w',
            'label': 'Admin Client Secret'
        },
        {
            'id': 'sync_groups',
            'type': 'boolean',
            'mode': 'w',
            'label': 'Enable Keycloak Group Sync (sync groups on user login)'
        },
        {
            'id': 'sync_users',
            'type': 'boolean',
            'mode': 'w',
            'label': 'Enable Keycloak User Sync (sync users to local storage)'
        },
        {
            'id': 'send_password_reset',
            'type': 'boolean',
            'mode': 'w',
            'label': 'Send password reset email (UPDATE_PASSWORD action)'
        },
        {
            'id': 'send_verify_email',
            'type': 'boolean',
            'mode': 'w',
            'label': 'Send verify email (VERIFY_EMAIL action)'
        },
        {
            'id': 'require_totp',
            'type': 'boolean',
            'mode': 'w',
            'label': 'Require 2FA/TOTP setup (CONFIGURE_TOTP action)'
        },
        {
            'id': 'email_link_lifespan',
            'type': 'int',
            'mode': 'w',
            'label': f'Email link lifespan in seconds (default: {DEFAULT_EMAIL_LINK_LIFESPAN} = 24h)'
        },
        {
            'id': 'redirect_uri',
            'type': 'string',
            'mode': 'w',
            'label': 'Redirect URI after completing Keycloak actions (optional)'
        },
        {
            'id': 'redirect_client_id',
            'type': 'string',
            'mode': 'w',
            'label': 'Client ID for redirect (required if redirect URI is set)'
        },
    )

    # Default property values
    title = ''
    server_url = ''
    realm = ''
    admin_client_id = ''
    admin_client_secret = ''
    sync_groups = False
    sync_users = False
    send_password_reset = True
    send_verify_email = True
    require_totp = False
    email_link_lifespan = DEFAULT_EMAIL_LINK_LIFESPAN
    redirect_uri = ''
    redirect_client_id = ''

    def __init__(self, id, title=None):
        """Initialize the plugin.

        Args:
            id: The plugin ID.
            title: Optional title for the plugin.
        """
        self._id = self.id = id
        self.title = title
        self._user_storage = OOBTree()

    def _get_user_storage(self):
        """Get the user storage, initializing if needed for existing plugins.

        Returns:
            OOBTree storage for user data.
        """
        if not hasattr(self, '_user_storage') or self._user_storage is None:
            self._user_storage = OOBTree()

        # Mark this as safeWrite - because this might/will change on GET request
        # if users are missing in there
        safeWrite(self._user_storage)
        return self._user_storage

    def get_client(self):
        """Get a configured KeycloakAdminClient, cached per thread.

        The client is stored as a volatile attribute (_v_client) so it
        persists per thread until the ZODB object is ghostified. The
        cache is invalidated when the connection config changes.

        Returns:
            Configured KeycloakAdminClient or None if not configured.
        """
        config = (
            self.server_url,
            self.realm,
            self.admin_client_id,
            self.admin_client_secret,
        )

        if not all(config):
            self._v_client = None
            self._v_client_config = None
            return None

        cached_config = getattr(self, '_v_client_config', None)
        if cached_config == config and getattr(self, '_v_client', None) is not None:
            return self._v_client

        self._v_client = KeycloakAdminClient(
            server_url=self.server_url,
            realm=self.realm,
            client_id=self.admin_client_id,
            client_secret=self.admin_client_secret,
        )
        self._v_client_config = config
        return self._v_client

    def _lookup_user_in_storage(self, username):
        """Look up a user in persistent storage and return PAS-formatted data.

        This method checks if a user exists in the persistent _user_storage
        and returns their data in the format expected by enumerateUsers.

        Args:
            username: The username to look up.

        Returns:
            Tuple containing a single user info dict if found, empty tuple otherwise.
        """
        storage = self._get_user_storage()
        if username in storage:
            return ({
                'id': username,
                'login': username,
                'pluginid': self.getId(),
            },)
        return ()

    def _parse_fullname(self, fullname):
        """Parse a fullname into first and last name parts.

        Args:
            fullname: Full name string (e.g., "John Doe").

        Returns:
            Tuple of (first_name, last_name).
        """
        if not fullname:
            return '', ''
        parts = fullname.split(' ', 1)
        first_name = parts[0]
        last_name = parts[1] if len(parts) > 1 else ''
        return first_name, last_name

    def _build_required_actions(self, include_totp=True):
        """Build list of required Keycloak actions based on plugin configuration.

        Args:
            include_totp: Whether to include TOTP action (False for existing users).

        Returns:
            List of action strings for Keycloak.
        """
        actions = []
        if self.send_password_reset:
            actions.append('UPDATE_PASSWORD')
        if self.send_verify_email:
            actions.append('VERIFY_EMAIL')
        if include_totp and self.require_totp:
            actions.append('CONFIGURE_TOTP')
        return actions

    def _send_actions_email(self, client, user_id, login, actions):
        """Send execute actions email to a user.

        Args:
            client: KeycloakAdminClient instance.
            user_id: The Keycloak user ID.
            login: The username (for logging).
            actions: List of required actions.

        Returns:
            True if email was sent successfully, False otherwise.
        """
        if not actions:
            return True

        try:
            client.send_execute_actions_email(
                user_id=user_id,
                actions=actions,
                lifespan=self.email_link_lifespan,
                redirect_uri=self.redirect_uri or None,
                client_id=self.redirect_client_id or None,
            )
            logger.info(
                f"Sent execute actions email to Keycloak user {login} "
                f"with actions: {actions}"
            )
            return True
        except KeycloakError as e:
            logger.error(f"Failed to send execute actions email to {login}: {e}")
            return False

    def _extract_user_data_from_request(self, login):
        """Extract user data (email, first_name, last_name) from the request.

        Supports both z3c.form widget format and standard form fields.

        Args:
            login: The username/login (used as fallback email).

        Returns:
            Tuple of (email, first_name, last_name).
        """
        form = api.portal.get().REQUEST.form

        # Try z3c.form widget format first (form.widgets.fieldname)
        email = form.get('form.widgets.email')
        fullname = form.get('form.widgets.fullname')

        # Fall back to standard form field names
        if not email:
            email = form.get('email', login)
        if not fullname:
            fullname = form.get('fullname', '')

        first_name, last_name = self._parse_fullname(fullname)
        return email, first_name, last_name

    #
    # IUserAdderPlugin implementation
    #
    @security.private
    def doAddUser(self, login, password):
        """Add a user to Keycloak.

        This method is called by PAS when a new user is being created
        (e.g., through the registration form).

        Args:
            login: The username/login for the new user.
            password: The password (may be ignored if we're sending a password reset email).

        Returns:
            Boolean indicating whether the user was added.
        """
        logger.info(f"KeycloakPlugin.doAddUser called for {login}")

        email, first_name, last_name = self._extract_user_data_from_request(login)

        # Get Keycloak client
        client = self.get_client()
        if not client:
            logger.error("Keycloak client not configured, cannot create user")
            return False

        try:
            # Create user in Keycloak
            user_id = client.create_user(
                username=login,
                email=email,
                first_name=first_name,
                last_name=last_name,
                enabled=True,
                email_verified=False,
            )

            if not user_id:
                logger.error(f"Failed to get user ID after creating user {login}")
                return False
            storage = self._get_user_storage()
            storage[login] = {
                  'email': email,
                  'firstName': first_name,
                  'lastName': last_name,
            }
            # Send execute actions email if any actions are configured
            actions = self._build_required_actions()
            self._send_actions_email(client, user_id, login, actions)
            # Note: Even if email fails, user was created, so we continue

            logger.info(f"Successfully created Keycloak user {login}")
            return True

        except KeycloakUserExistsError:
            logger.warning(f"User {login} already exists in Keycloak")
            # User exists - this might be intentional (re-registration)
            # Try to get the existing user and send the actions email
            # Note: For existing users, we don't require TOTP setup again
            user_id = client.get_user_id_by_username(login)
            if user_id:
                actions = self._build_required_actions(include_totp=False)
                self._send_actions_email(client, user_id, login, actions)
            return True  # Consider it success since user exists

        except KeycloakError as e:
            logger.error(f"Failed to create Keycloak user {login}: {e}")
            return False

    @security.private
    def enumerateUsers(
        self,
        id=None,
        login=None,
        exact_match=False,
        sort_by=None,
        max_results=None,
        **kw
    ):
        """Enumerate users matching the given criteria.

        This method is called by PAS to find users. For exact single-user
        lookups (by id or login), it first checks the persistent _user_storage
        to avoid unnecessary Keycloak API calls. For search queries, it queries
        Keycloak directly.

        Args:
            id: User ID to match (in Keycloak, this is the username).
            login: Login name to match (username in Keycloak).
            exact_match: If True, require exact matches.
            sort_by: Field to sort by (not supported by Keycloak API).
            max_results: Maximum number of results to return.
            **kw: Additional keyword arguments (email, fullname supported).

        Returns:
            Tuple of user info dicts with keys: id, login, pluginid.
        """
        search_id = id or login
        email = kw.get('email')
        fullname = kw.get('fullname')

        # Optimization: For exact single-user lookups by id/login, check storage first
        if search_id and exact_match and not email and not fullname:
            storage = self._get_user_storage()
            stored_result = self._lookup_user_in_storage(search_id)
            if stored_result:
                return stored_result

        client = self.get_client()
        if not client:
            logger.debug("Keycloak client not configured, skipping enumeration")
            return ()

        try:
            # Build search parameters for Keycloak
            if search_id:
                # Search by username
                users = client.search_users(
                    username=search_id,
                    exact=exact_match,
                    max_results=max_results,
                )
            elif email:
                # Search by email
                users = client.search_users(
                    email=email,
                    exact=exact_match,
                    max_results=max_results,
                )
            elif fullname:
                # Search by name (general search)
                users = client.search_users(
                    search=fullname,
                    exact=exact_match,
                    max_results=max_results,
                )
            else:
                # No search criteria - return all users with a limit
                users = client.search_users(
                    max_results=max_results or DEFAULT_MAX_USERS,
                )

            # Convert Keycloak users to PAS format and store user data
            result = []
            plugin_id = self.getId()
            storage = self._get_user_storage()

            for user in users:
                username = user.get('username', '')
                if not username:
                    continue

                # For exact match, verify the match is exact
                if exact_match and search_id:
                    if username.lower() != search_id.lower():
                        continue

                # Store user data for property lookups (persistent)
                storage[username] = extract_user_storage_data(user)

                result.append({
                    'id': username,
                    'login': username,
                    'pluginid': plugin_id,
                })

            # Apply max_results if specified
            if max_results and len(result) > max_results:
                result = result[:max_results]

            return tuple(result)

        except Exception as e:
            logger.error(f"Error enumerating users from Keycloak: {e}")
            return ()

    @security.private
    def getPropertiesForUser(self, user, request=None):
        """Get properties for a user from persistent storage.

        This method is called by PAS to get user properties.
        Note: Groups are now managed as native Plone groups via sync,
        so this method only handles users.

        Args:
            user: The user object (provides getId()).
            request: The current request (optional).

        Returns:
            Dict of properties (email, fullname).
        """
        principal_id = user.getId()

        # Check if this is a group - if so, return empty (groups are native Plone)
        try:
            is_group_method = getattr(user, 'isGroup', None)
            if callable(is_group_method) and is_group_method() is True:
                return {}
        except Exception:
            pass

        # It's a user - check user storage
        user_storage = self._get_user_storage()
        user_data = user_storage.get(principal_id)

        if user_data is None:
            # Not in storage, fetch from Keycloak
            client = self.get_client()
            if not client:
                logger.debug("Keycloak client not configured")
                return {}

            keycloak_user = client.get_user(principal_id)
            if keycloak_user:
                user_data = extract_user_storage_data(keycloak_user)
                user_storage[principal_id] = user_data
            else:
                return {}

        # Convert stored data to Plone properties
        first_name = user_data.get('firstName', '')
        last_name = user_data.get('lastName', '')

        return {
            'email': user_data.get('email', ''),
            'fullname': f"{first_name} {last_name}".strip(),
        }

    def updateUser(self, user_id, login_name):
        """Update the login name of the user with id user_id.

        We do not store the login_name, return True.
        There seems to be a bug in the _updateLoginName, resp. it does
        not uphold the description.

        Args:
            user_id: The user ID.
            login_name: The new login name.

        Returns:
            True always.
        """
        return True


InitializeClass(KeycloakPlugin)

classImplements(
    KeycloakPlugin,
    IKeycloakPlugin,
    IPropertiesPlugin,
    IUserAdderPlugin,
    IUserEnumerationPlugin,
)
