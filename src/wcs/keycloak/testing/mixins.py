"""Shared test utilities and fixtures for Keycloak integration tests.

This module provides common test infrastructure used across all Keycloak tests:
- KeycloakTestMixin: Mixin class for Keycloak test utilities
- Constants for test configuration
- Helper methods for user/group cleanup
"""
from plone import api
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserAdderPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from wcs.keycloak.client import KeycloakAdminClient
from wcs.keycloak.plugin import manage_addKeycloakPlugin
import requests
import transaction


# Keycloak test server configuration
KEYCLOAK_SERVER_URL = 'http://localhost:8000'
KEYCLOAK_REALM = 'saml-test'
KEYCLOAK_ADMIN_USER = 'admin'
KEYCLOAK_ADMIN_PASSWORD = 'admin'

# Service account client configuration for tests that need plugin.get_client()
SERVICE_ACCOUNT_CLIENT_ID = 'plone-test-service-account'
SERVICE_ACCOUNT_CLIENT_SECRET = 'test-secret-for-enumeration'


class KeycloakTestMixin:
    """Mixin providing common Keycloak test utilities.

    Provides methods for creating admin clients, authenticating,
    and cleaning up test users and groups.

    Attributes:
        client: KeycloakAdminClient instance for tests.
        _created_users: List of usernames created during tests.
        _created_groups: List of group IDs created during tests.
    """

    _created_users = None
    _created_groups = None

    def _create_admin_client(self):
        """Create a KeycloakAdminClient configured for testing.

        Returns:
            KeycloakAdminClient instance with password grant authentication.
        """
        client = KeycloakAdminClient(
            server_url=KEYCLOAK_SERVER_URL,
            realm=KEYCLOAK_REALM,
            client_id='admin-cli',
            client_secret='',  # Not used for password grant
        )
        # Override authentication to use password grant on master realm
        client._authenticate = lambda: self._authenticate_admin(client)
        return client

    def _authenticate_admin(self, client):
        """Authenticate using password grant for admin access.

        Args:
            client: KeycloakAdminClient instance to authenticate.

        Returns:
            Access token string.
        """
        token_url = f'{KEYCLOAK_SERVER_URL}/realms/master/protocol/openid-connect/token'
        data = {
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': KEYCLOAK_ADMIN_USER,
            'password': KEYCLOAK_ADMIN_PASSWORD,
        }
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        token_data = response.json()
        client._access_token = token_data['access_token']
        return client._access_token

    def _cleanup_user(self, username):
        """Delete a user from Keycloak by username.

        Args:
            username: Username of the user to delete.
        """
        user_id = self.client.get_user_id_by_username(username)
        if user_id:
            url = f"{self.client._get_admin_url()}/users/{user_id}"
            self.client._make_request('DELETE', url)

    def _cleanup_group(self, group_id):
        """Delete a group from Keycloak by ID.

        Args:
            group_id: UUID of the group to delete.
        """
        if group_id:
            self.client.delete_group(group_id)

    def _setup_keycloak_client(self):
        """Set up Keycloak client and user/group tracking for tests."""
        self.client = self._create_admin_client()
        self._created_users = []
        self._created_groups = []

    def _teardown_keycloak_client(self):
        """Clean up test users, groups and close client session."""
        for username in self._created_users:
            self._cleanup_user(username)
        self._created_users = []
        for group_id in self._created_groups:
            self._cleanup_group(group_id)
        self._created_groups = []
        if self.client and hasattr(self.client, '_session'):
            self.client._session.close()
        self.client = None

    def _create_service_account_client(self):
        """Create a service account client with manage-users permissions in Keycloak."""
        # First, delete if exists
        self._delete_service_account_client()

        clients_url = f'{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients'
        client_data = {
            'clientId': SERVICE_ACCOUNT_CLIENT_ID,
            'name': 'Plone Test Service Account',
            'enabled': True,
            'clientAuthenticatorType': 'client-secret',
            'secret': SERVICE_ACCOUNT_CLIENT_SECRET,
            'serviceAccountsEnabled': True,
            'publicClient': False,
            'standardFlowEnabled': False,
            'directAccessGrantsEnabled': False,
            'protocol': 'openid-connect',
        }
        response = self.client._make_request('POST', clients_url, json=client_data)
        if response.status_code != 201:
            raise Exception(f'Failed to create service account client: {response.text}')

        # Get the client's internal ID
        response = self.client._make_request(
            'GET', clients_url, params={'clientId': SERVICE_ACCOUNT_CLIENT_ID}
        )
        response.raise_for_status()
        clients = response.json()
        client_uuid = clients[0]['id']

        # Get the service account user
        service_account_url = f'{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{client_uuid}/service-account-user'
        response = self.client._make_request('GET', service_account_url)
        response.raise_for_status()
        service_account_user_id = response.json()['id']

        # Get the realm-management client ID
        response = self.client._make_request(
            'GET', clients_url, params={'clientId': 'realm-management'}
        )
        response.raise_for_status()
        realm_management_uuid = response.json()[0]['id']

        # Get roles from realm-management client
        roles_url = f'{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients/{realm_management_uuid}/roles'
        response = self.client._make_request('GET', roles_url)
        response.raise_for_status()
        roles = response.json()

        roles_to_assign = []
        for role in roles:
            if role['name'] in ('manage-users', 'view-users', 'query-users'):
                roles_to_assign.append(role)

        # Assign roles to the service account
        role_mapping_url = f'{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/users/{service_account_user_id}/role-mappings/clients/{realm_management_uuid}'
        response = self.client._make_request('POST', role_mapping_url, json=roles_to_assign)
        if response.status_code != 204:
            raise Exception(f'Failed to assign roles: {response.text}')

    def _delete_service_account_client(self):
        """Delete the service account client if it exists."""
        clients_url = f'{KEYCLOAK_SERVER_URL}/admin/realms/{KEYCLOAK_REALM}/clients'
        response = self.client._make_request(
            'GET', clients_url, params={'clientId': SERVICE_ACCOUNT_CLIENT_ID}
        )
        if response.status_code == 200:
            for client in response.json():
                delete_url = f'{clients_url}/{client["id"]}'
                self.client._make_request('DELETE', delete_url)

    def _configure_plugin_for_service_account(self):
        """Configure Keycloak plugin to use the service account client."""
        acl_users = api.portal.get_tool('acl_users')
        if 'keycloak' not in acl_users:
            manage_addKeycloakPlugin(acl_users, 'keycloak', title='Keycloak')

        plugin = acl_users['keycloak']
        plugin.server_url = KEYCLOAK_SERVER_URL
        plugin.realm = KEYCLOAK_REALM
        plugin.admin_client_id = SERVICE_ACCOUNT_CLIENT_ID
        plugin.admin_client_secret = SERVICE_ACCOUNT_CLIENT_SECRET
        transaction.commit()


class KeycloakPluginTestMixin(KeycloakTestMixin):
    """Extended mixin with Keycloak plugin setup utilities for integration tests.

    Provides methods for setting up the Keycloak PAS plugin with various
    interface activations and creating test users.
    """

    def _setup_keycloak_plugin(
        self,
        activate_user_adder=True,
        activate_enumeration=False,
        activate_properties=False,
        deactivate_source_users=True,
        configure_connection=True,
    ):
        """Add keycloak plugin to acl_users and activate it.

        Args:
            activate_user_adder: Activate IUserAdderPlugin interface.
            activate_enumeration: Activate IUserEnumerationPlugin interface.
            activate_properties: Activate IPropertiesPlugin interface.
            deactivate_source_users: Deactivate source_users for IUserAdderPlugin.
            configure_connection: Configure connection settings for service account.
        """
        acl_users = api.portal.get_tool('acl_users')

        if 'keycloak' not in acl_users:
            manage_addKeycloakPlugin(
                acl_users,
                'keycloak',
                title='Keycloak'
            )

        plugin = acl_users['keycloak']

        # Configure connection properties
        if configure_connection:
            plugin.server_url = KEYCLOAK_SERVER_URL
            plugin.realm = KEYCLOAK_REALM
            plugin.admin_client_id = SERVICE_ACCOUNT_CLIENT_ID
            plugin.admin_client_secret = SERVICE_ACCOUNT_CLIENT_SECRET

        plugin.manage_changeProperties(
            send_password_reset=False,
            send_verify_email=False,
            require_totp=False,
        )

        plugins = acl_users.plugins

        if activate_user_adder:
            plugins.activatePlugin(IUserAdderPlugin, 'keycloak')
            if deactivate_source_users:
                active_plugins = list(plugins.listPluginIds(IUserAdderPlugin))
                if 'source_users' in active_plugins:
                    plugins.deactivatePlugin(IUserAdderPlugin, 'source_users')

        if activate_enumeration:
            plugins.activatePlugin(IUserEnumerationPlugin, 'keycloak')

        if activate_properties:
            plugins.activatePlugin(IPropertiesPlugin, 'keycloak')
            # Move keycloak to the top of IPropertiesPlugin order so it takes
            # precedence over mutable_properties (which has empty default values)
            plugins.movePluginsTop(IPropertiesPlugin, ['keycloak'])

        transaction.commit()

    def _cleanup_keycloak_plugin(self):
        """Remove keycloak plugin from acl_users."""
        acl_users = api.portal.get_tool('acl_users')
        if 'keycloak' in acl_users:
            acl_users.manage_delObjects(['keycloak'])
            transaction.commit()

    def _create_keycloak_test_user(self, username, email, fullname):
        """Create a test user in Keycloak via the plugin.

        Args:
            username: The username for the new user.
            email: The email for the new user.
            fullname: The fullname for the new user.

        Returns:
            The username of the created user.
        """
        self._cleanup_user(username)
        self._created_users.append(username)

        acl_users = api.portal.get_tool('acl_users')
        plugin = acl_users['keycloak']

        self.request.form = {
            'form.widgets.email': email,
            'form.widgets.fullname': fullname,
        }

        result = plugin.doAddUser(username, 'password123')
        self.assertTrue(result, f'Failed to create test user {username}')
        transaction.commit()
        return username
