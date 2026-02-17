"""Tests for basic KeycloakPlugin functionality.

This module contains tests for:
- Plugin instantiation
- Interface implementation
- Default property values
- Storage initialization
"""
from BTrees.OOBTree import OOBTree
from Products.PluggableAuthService.interfaces.plugins import IPropertiesPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserAdderPlugin
from wcs.keycloak.plugin import KeycloakPlugin
from wcs.keycloak.tests import FunctionalTesting


class TestKeycloakPlugin(FunctionalTesting):
    """Integration tests for the KeycloakPlugin."""

    def setUp(self):
        super().setUp()
        self.grant('Manager')

    def test_plugin_can_be_instantiated(self):
        plugin = KeycloakPlugin('test_plugin', 'Test Plugin')

        self.assertEqual(plugin.id, 'test_plugin')
        self.assertEqual(plugin.title, 'Test Plugin')

    def test_plugin_implements_user_adder_interface(self):
        plugin = KeycloakPlugin('test', 'Test')

        self.assertTrue(IUserAdderPlugin.providedBy(plugin))

    def test_plugin_default_properties(self):
        plugin = KeycloakPlugin('test', 'Test')

        self.assertTrue(plugin.send_password_reset)
        self.assertTrue(plugin.send_verify_email)
        self.assertFalse(plugin.require_totp)
        self.assertEqual(plugin.email_link_lifespan, 86400)


class TestKeycloakPluginStorage(FunctionalTesting):
    """Tests for KeycloakPlugin storage functionality."""

    def test_plugin_initializes_with_oobtree_storage(self):
        plugin = KeycloakPlugin('test_plugin')
        self.assertIsInstance(plugin._user_storage, OOBTree)

    def test_get_user_storage_returns_existing_storage(self):
        plugin = KeycloakPlugin('test_plugin')
        plugin._user_storage['testuser'] = {'email': 'test@example.com'}

        storage = plugin._get_user_storage()

        self.assertIn('testuser', storage)
        self.assertEqual(storage['testuser']['email'], 'test@example.com')

    def test_get_user_storage_initializes_missing_storage(self):
        plugin = KeycloakPlugin('test_plugin')
        del plugin._user_storage

        storage = plugin._get_user_storage()

        self.assertIsInstance(storage, OOBTree)

    def test_update_user_returns_true(self):
        plugin = KeycloakPlugin('test_plugin')

        result = plugin.updateUser('user_id', 'login_name')

        self.assertTrue(result)

    def test_plugin_implements_properties_plugin_interface(self):
        self.assertTrue(IPropertiesPlugin.implementedBy(KeycloakPlugin))
