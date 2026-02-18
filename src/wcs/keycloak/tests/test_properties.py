"""Tests for KeycloakPlugin user properties functionality.

This module contains tests for:
- IPropertiesPlugin implementation
- User property retrieval (fullname, email)
- Property storage and caching
- Browser-based property display
"""

from plone import api
from Products.CMFCore.permissions import AddPortalMember
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin
from Products.PluggableAuthService.PropertiedUser import PropertiedUser
from unittest.mock import Mock
from wcs.keycloak.testing.mixins import KeycloakPluginTestMixin
from wcs.keycloak.tests import FunctionalTesting

import requests
import transaction


class TestKeycloakUserPropertiesInBrowser(KeycloakPluginTestMixin, FunctionalTesting):
    """Browser tests for user properties with Keycloak.

    These tests verify that user properties (fullname) work correctly
    when users come from Keycloak.

    Note: Group enumeration and introspection have been removed from the
    Keycloak plugin. Groups are now synced to native Plone groups via
    the group sync feature.
    """

    def setUp(self):
        super().setUp()
        self.grant("Manager")

        # Set up Keycloak admin client (uses password grant)
        self._setup_keycloak_client()

        # Create service account client in Keycloak with proper permissions
        self._create_service_account_client()

        # Setup keycloak plugin in acl_users (configures connection properties)
        self._setup_keycloak_plugin(
            activate_user_adder=False,
            activate_enumeration=True,
            activate_properties=True,
        )

    def tearDown(self):
        self._cleanup_keycloak_plugin()
        self._delete_service_account_client()
        self._teardown_keycloak_client()
        super().tearDown()

    def test_users_overview_page_renders(self):
        response = requests.get(
            f"{self.portal_url}/@@usergroup-userprefs",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("User Search", response.text)

    def test_get_properties_for_user_returns_fullname(self):
        username = "test_props_user"
        email = "test_props_user@example.com"
        first_name = "Jane"
        last_name = "Smith"
        self._cleanup_user(username)
        self._created_users.append(username)
        self.client.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )

        acl_users = api.portal.get_tool("acl_users")
        keycloak_plugin = acl_users.keycloak

        user = PropertiedUser(username)

        properties = keycloak_plugin.getPropertiesForUser(user, self.request)

        self.assertIn("fullname", properties)
        self.assertEqual(properties["fullname"], f"{first_name} {last_name}")
        self.assertIn("email", properties)
        self.assertEqual(properties["email"], email)

    def test_member_get_property_fullname_returns_keycloak_value(self):
        username = "test_member_props_user"
        email = "test_member_props@example.com"
        first_name = "Bob"
        last_name = "Jones"
        self._cleanup_user(username)
        self._created_users.append(username)
        self.client.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )

        acl_users = api.portal.get_tool("acl_users")
        plugins = acl_users.plugins
        if "keycloak" not in plugins.listPluginIds(IPropertiesPlugin):
            plugins.activatePlugin(IPropertiesPlugin, "keycloak")

        plugins.movePluginsTop(IPropertiesPlugin, ["keycloak"])

        transaction.commit()

        mtool = api.portal.get_tool("portal_membership")
        member = mtool.getMemberById(username)

        self.assertIsNotNone(member, f"Member {username} not found")
        fullname = member.getProperty("fullname", "")
        self.assertEqual(fullname, f"{first_name} {last_name}")

    def test_users_overview_shows_user_fullname(self):
        username = "test_fullname_user"
        email = "test_fullname_user@example.com"
        first_name = "John"
        last_name = "Doe"
        self._cleanup_user(username)
        self._created_users.append(username)
        self.client.create_user(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
        )

        acl_users = api.portal.get_tool("acl_users")
        plugins = acl_users.plugins
        if "keycloak" not in plugins.listPluginIds(IPropertiesPlugin):
            plugins.activatePlugin(IPropertiesPlugin, "keycloak")

        plugins.movePluginsTop(IPropertiesPlugin, ["keycloak"])

        transaction.commit()

        response = requests.get(
            f"{self.portal_url}/@@usergroup-userprefs",
            auth=self.credentials,
            params={"searchstring": username},
        )

        self.assertEqual(response.status_code, 200)

        expected_fullname = f"{first_name} {last_name}"
        self.assertIn(expected_fullname, response.text)


class TestKeycloakPropertiesPluginIntegration(
    KeycloakPluginTestMixin, FunctionalTesting
):
    """Integration tests for user properties with the plugin installed in PAS."""

    def setUp(self):
        super().setUp()
        self.grant("Manager")
        self._setup_keycloak_client()
        self._create_service_account_client()
        self._setup_keycloak_plugin(
            activate_user_adder=True,
            activate_enumeration=True,
            activate_properties=True,
        )

        self.portal.manage_permission(AddPortalMember, ["Anonymous"], acquire=0)
        transaction.commit()

    def tearDown(self):
        self._delete_service_account_client()
        self._teardown_keycloak_client()
        super().tearDown()

    def test_enumerate_users_populates_storage(self):
        username = "test_storage_enum_001"
        email = "test_storage_enum_001@example.com"

        self._create_keycloak_test_user(username, email, "Storage Test User")

        acl_users = api.portal.get_tool("acl_users")
        plugin = acl_users["keycloak"]

        plugin.enumerateUsers(id=username, exact_match=True)

        storage = plugin._get_user_storage()
        self.assertIn(username, storage)
        self.assertEqual(storage[username]["email"], email)

    def test_get_properties_returns_user_properties(self):
        username = "test_props_001"
        email = "test_props_001@example.com"
        fullname = "Properties Test User"

        self._create_keycloak_test_user(username, email, fullname)

        acl_users = api.portal.get_tool("acl_users")
        plugin = acl_users["keycloak"]

        plugin.enumerateUsers(id=username, exact_match=True)

        mock_user = Mock()
        mock_user.getId.return_value = username

        properties = plugin.getPropertiesForUser(mock_user)

        self.assertEqual(properties["email"], email)
        self.assertEqual(properties["fullname"], fullname)

    def test_get_properties_fetches_from_keycloak_if_not_in_storage(self):
        username = "test_props_fetch_002"
        email = "test_props_fetch_002@example.com"
        fullname = "Fetch Test User"

        self._create_keycloak_test_user(username, email, fullname)

        acl_users = api.portal.get_tool("acl_users")
        plugin = acl_users["keycloak"]

        plugin._user_storage.clear()

        mock_user = Mock()
        mock_user.getId.return_value = username

        properties = plugin.getPropertiesForUser(mock_user)

        self.assertEqual(properties["email"], email)
        self.assertEqual(properties["fullname"], fullname)

        self.assertIn(username, plugin._user_storage)

    def test_get_properties_returns_empty_dict_for_unknown_user(self):
        acl_users = api.portal.get_tool("acl_users")
        plugin = acl_users["keycloak"]

        mock_user = Mock()
        mock_user.getId.return_value = "nonexistent_user_xyz"

        properties = plugin.getPropertiesForUser(mock_user)

        self.assertEqual(properties, {})
