"""Tests for KeycloakPlugin user creation functionality.

This module contains tests for:
- IUserAdderPlugin implementation
- doAddUser method
- User creation in Keycloak
- Duplicate user handling
"""

from plone import api
from Products.CMFCore.permissions import AddPortalMember
from Products.PluggableAuthService.interfaces.plugins import IUserAdderPlugin
from wcs.keycloak.testing.mixins import KeycloakPluginTestMixin
from wcs.keycloak.tests import FunctionalTesting

import transaction


class TestKeycloakPluginIntegration(KeycloakPluginTestMixin, FunctionalTesting):
    """Integration tests for user creation with the KeycloakPlugin."""

    def setUp(self):
        super().setUp()
        self.grant("Manager")
        self._setup_keycloak_client()
        self._create_service_account_client()
        self._setup_keycloak_plugin(activate_user_adder=True)

        self.portal.manage_permission(AddPortalMember, ["Anonymous"], acquire=0)
        transaction.commit()

    def tearDown(self):
        self._delete_service_account_client()
        self._teardown_keycloak_client()
        super().tearDown()

    def test_plugin_is_active(self):
        acl_users = api.portal.get_tool("acl_users")
        plugins = acl_users.plugins

        active_plugins = list(plugins.listPluginIds(IUserAdderPlugin))

        self.assertIn("keycloak", active_plugins)
        self.assertNotIn("source_users", active_plugins)

    def test_add_user_creates_user_in_keycloak(self):
        username = "test_integration_user_001"
        email = "test_integration_user_001@example.com"

        self._cleanup_user(username)
        self._created_users.append(username)

        acl_users = api.portal.get_tool("acl_users")
        plugin = acl_users["keycloak"]

        self.request.form = {
            "form.widgets.email": email,
            "form.widgets.fullname": "Test User",
        }

        result = plugin.doAddUser(username, "password123")

        self.assertTrue(result, "doAddUser should return True on success")

        keycloak_user = self.client.get_user(username)
        self.assertIsNotNone(keycloak_user, f"User {username} should exist in Keycloak")
        self.assertEqual(keycloak_user["username"], username)
        self.assertEqual(keycloak_user["email"], email)
        self.assertEqual(keycloak_user["firstName"], "Test")
        self.assertEqual(keycloak_user["lastName"], "User")
        self.assertTrue(keycloak_user["enabled"])

    def test_duplicate_user_handling(self):
        username = "test_duplicate_user_004"
        email = "test_duplicate_user_004@example.com"

        self._cleanup_user(username)
        self._created_users.append(username)

        acl_users = api.portal.get_tool("acl_users")
        plugin = acl_users["keycloak"]

        self.request.form = {
            "form.widgets.email": email,
            "form.widgets.fullname": "Duplicate Test",
        }

        result1 = plugin.doAddUser(username, "password123")
        self.assertTrue(result1)

        result2 = plugin.doAddUser(username, "password456")
        self.assertTrue(result2, "Duplicate user creation should be handled gracefully")

        keycloak_user = self.client.get_user(username)
        self.assertIsNotNone(keycloak_user)
