"""Tests for KeycloakPlugin user enumeration functionality.

This module contains tests for:
- IUserEnumerationPlugin implementation
- User search by id, login, email
- Exact and partial matching
- Max results limiting
"""

from plone import api
from Products.CMFCore.permissions import AddPortalMember
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from wcs.keycloak.testing.mixins import KeycloakPluginTestMixin
from wcs.keycloak.testing.mixins import KeycloakTestMixin
from wcs.keycloak.tests import FunctionalTesting

import requests
import transaction


class TestKeycloakEnumerateUsers(KeycloakTestMixin, FunctionalTesting):
    """Tests for the enumerateUsers method of KeycloakPlugin."""

    def setUp(self):
        super().setUp()
        self.grant("Manager")

        # Set up admin client first (uses password grant)
        self._setup_keycloak_client()

        # Create service account client in Keycloak with proper permissions
        self._create_service_account_client()

        # Configure the plugin for service account (adds to acl_users)
        self._configure_plugin_for_service_account()

        # Get the plugin reference for tests
        acl_users = api.portal.get_tool("acl_users")
        self.plugin = acl_users["keycloak"]

    def tearDown(self):
        # Clean up service account client
        self._delete_service_account_client()
        self._teardown_keycloak_client()
        super().tearDown()

    def test_plugin_implements_user_enumeration_interface(self):
        self.assertTrue(
            IUserEnumerationPlugin.providedBy(self.plugin),
            "Plugin should implement IUserEnumerationPlugin",
        )

    def test_enumerate_users_by_id(self):
        username = "test_enum_by_id_123"
        email = "test_enum_by_id_123@example.com"

        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email=email,
            first_name="Enumerate",
            last_name="ById",
        )

        results = self.plugin.enumerateUsers(id=username, exact_match=True)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], username)
        self.assertEqual(results[0]["login"], username)
        self.assertEqual(results[0]["pluginid"], "keycloak")

    def test_enumerate_users_by_login(self):
        username = "test_enum_by_login_123"
        email = "test_enum_by_login_123@example.com"

        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email=email,
            first_name="Enumerate",
            last_name="ByLogin",
        )

        results = self.plugin.enumerateUsers(login=username, exact_match=True)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], username)
        self.assertEqual(results[0]["login"], username)

    def test_enumerate_users_by_email(self):
        username = "test_enum_by_email_123"
        email = "test_enum_by_email_unique@example.com"

        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email=email,
            first_name="Enumerate",
            last_name="ByEmail",
        )

        results = self.plugin.enumerateUsers(email=email, exact_match=True)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], username)

    def test_enumerate_users_no_criteria_returns_all_users(self):
        username = "test_enum_all_users"
        email = "test_enum_all_users@example.com"

        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email=email,
            first_name="Enumerate",
            last_name="AllUsers",
        )

        results = self.plugin.enumerateUsers()

        usernames = [r["id"] for r in results]
        self.assertIn(username, usernames)

    def test_enumerate_users_not_found(self):
        results = self.plugin.enumerateUsers(
            id="nonexistent_user_xyz_999", exact_match=True
        )

        self.assertEqual(len(results), 0)

    def test_enumerate_users_max_results(self):
        results = self.plugin.enumerateUsers(id="a", max_results=2)

        self.assertTrue(
            len(results) <= 2, "Results should not exceed max_results limit of 2"
        )


class TestKeycloakUserEnumerationPluginIntegration(
    KeycloakPluginTestMixin, FunctionalTesting
):
    """Integration tests for user enumeration with the plugin installed in PAS."""

    def setUp(self):
        super().setUp()
        self.grant("Manager")
        self._setup_keycloak_client()
        self._create_service_account_client()
        self._setup_keycloak_plugin(
            activate_user_adder=True,
            activate_enumeration=True,
        )

        self.portal.manage_permission(AddPortalMember, ["Anonymous"], acquire=0)
        transaction.commit()

    def tearDown(self):
        self._delete_service_account_client()
        self._teardown_keycloak_client()
        super().tearDown()

    def test_user_enumeration_plugin_is_active(self):
        acl_users = api.portal.get_tool("acl_users")
        plugins = acl_users.plugins

        active_plugins = list(plugins.listPluginIds(IUserEnumerationPlugin))

        self.assertIn("keycloak", active_plugins)

    def test_enumerate_users_returns_keycloak_user(self):
        username = "test_enum_user_001"
        email = "test_enum_user_001@example.com"

        self._create_keycloak_test_user(username, email, "Enum Test User")

        acl_users = api.portal.get_tool("acl_users")
        plugin = acl_users["keycloak"]

        results = plugin.enumerateUsers(id=username, exact_match=True)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], username)
        self.assertEqual(results[0]["login"], username)
        self.assertEqual(results[0]["pluginid"], "keycloak")

    def test_enumerate_users_with_partial_match(self):
        username = "test_partial_enum_002"
        email = "test_partial_enum_002@example.com"

        self._create_keycloak_test_user(username, email, "Partial Match User")

        acl_users = api.portal.get_tool("acl_users")
        plugin = acl_users["keycloak"]

        results = plugin.enumerateUsers(id="partial_enum", exact_match=False)

        usernames = [r["id"] for r in results]
        self.assertIn(username, usernames)

    def test_enumerate_users_without_search_criteria_returns_all_users(self):
        username = "test_all_users_enum_006"
        email = "test_all_users_enum_006@example.com"

        self._create_keycloak_test_user(username, email, "All Users Test")

        acl_users = api.portal.get_tool("acl_users")
        plugin = acl_users["keycloak"]

        results = plugin.enumerateUsers()

        usernames = [r["id"] for r in results]
        self.assertIn(username, usernames)

    def test_search_user_via_rest_api_returns_keycloak_user(self):
        username = "test_restapi_enum_003"
        email = "test_restapi_enum_003@example.com"

        self._create_keycloak_test_user(username, email, "REST API Test User")

        response = requests.get(
            f"{self.portal_url}/@users?query={username}",
            headers=self.api_headers,
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        response_data = response.json()
        user_ids = [user["id"] for user in response_data]

        self.assertIn(username, user_ids)

        keycloak_user = next((u for u in response_data if u["id"] == username), None)
        self.assertIsNotNone(keycloak_user)
        self.assertEqual(keycloak_user["id"], username)

    def test_plone_user_management_shows_keycloak_users_without_search(self):
        username = "test_usermgmt_enum_004"
        email = "test_usermgmt_enum_004@example.com"

        self._create_keycloak_test_user(username, email, "User Management Test")

        response = requests.get(
            f"{self.portal_url}/@@usergroup-userprefs",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(username, response.text)

    def test_rest_api_users_endpoint_with_search_query_parameter(self):
        username = "test_query_param_005"
        email = "test_query_param_005@example.com"

        self._create_keycloak_test_user(username, email, "Query Param User")

        response = requests.get(
            f"{self.portal_url}/@users?query={username}",
            headers=self.api_headers,
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        response_data = response.json()
        user_ids = [user["id"] for user in response_data]

        self.assertIn(username, user_ids)
