"""Tests for Keycloak user synchronization functionality."""

from plone import api
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from wcs.keycloak.testing.mixins import KeycloakPluginTestMixin
from wcs.keycloak.tests import FunctionalTesting
from wcs.keycloak.user_sync import is_user_sync_enabled
from wcs.keycloak.user_sync import sync_all_users

import requests
import transaction


class UserSyncTestBase(KeycloakPluginTestMixin, FunctionalTesting):
    """Base class for user sync tests with common setUp/tearDown."""

    def setUp(self):
        super().setUp()
        self.grant("Manager")
        self._setup_keycloak_client()
        self._create_service_account_client()
        self._setup_keycloak_plugin(
            activate_user_adder=True,
            activate_enumeration=False,
        )

    def tearDown(self):
        self._cleanup_keycloak_plugin()
        self._delete_service_account_client()
        self._teardown_keycloak_client()
        super().tearDown()


class TestUserSyncEnabled(UserSyncTestBase):
    def test_user_sync_disabled_by_default(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]

        self.assertFalse(
            plugin.sync_users,
            "sync_users should be False by default",
        )

    def test_user_sync_not_enabled_when_property_is_false(self):
        self.assertFalse(
            is_user_sync_enabled(),
            "User sync should not be enabled when sync_users is False",
        )

    def test_user_sync_enabled_when_configured(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_users = True
        transaction.commit()

        self.assertTrue(
            is_user_sync_enabled(),
            "User sync should be enabled when sync_users is True and client is configured",
        )

    def test_user_sync_disabled_without_client_config(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_users = True
        plugin.server_url = ""
        transaction.commit()

        self.assertFalse(
            is_user_sync_enabled(),
            "User sync should not be enabled without a configured client",
        )

    def test_user_sync_not_enabled_when_enumeration_active(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_users = True

        acl_users = api.portal.get_tool("acl_users")
        acl_users.plugins.activatePlugin(IUserEnumerationPlugin, "keycloak")
        transaction.commit()

        self.assertFalse(
            is_user_sync_enabled(),
            "User sync should not be enabled when enumeration plugin is active",
        )

    def test_user_sync_enabled_when_enumeration_not_active(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_users = True
        transaction.commit()

        self.assertTrue(
            is_user_sync_enabled(),
            "User sync should be enabled when enumeration plugin is not active",
        )


class TestSyncAllUsers(UserSyncTestBase):
    def test_sync_creates_users_in_storage(self):
        username = "test_usersync_create_001"
        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email="test_usersync_create_001@example.com",
            first_name="Sync",
            last_name="Test",
        )

        stats = sync_all_users()

        plugin = api.portal.get_tool("acl_users")["keycloak"]
        storage = plugin._get_user_storage()

        self.assertIn(username, storage, "Synced user should be in storage")
        self.assertEqual(
            storage[username]["email"], "test_usersync_create_001@example.com"
        )
        self.assertEqual(storage[username]["firstName"], "Sync")
        self.assertEqual(storage[username]["lastName"], "Test")
        self.assertGreater(
            stats["users_synced"], 0, "Should have synced at least one user"
        )

    def test_sync_updates_existing_user_properties(self):
        username = "test_usersync_update_001"
        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email="old_email@example.com",
            first_name="Old",
            last_name="Name",
        )

        # Initial sync
        sync_all_users()

        # Update user in Keycloak
        user_id = self.client.get_user_id_by_username(username)
        url = f"{self.client._get_admin_url()}/users/{user_id}"
        self.client._make_request(
            "PUT",
            url,
            json={
                "email": "new_email@example.com",
                "firstName": "New",
                "lastName": "Updated",
            },
        )

        # Sync again
        sync_all_users()

        plugin = api.portal.get_tool("acl_users")["keycloak"]
        storage = plugin._get_user_storage()

        self.assertEqual(
            storage[username]["email"],
            "new_email@example.com",
            "Email should be updated after sync",
        )
        self.assertEqual(storage[username]["firstName"], "New")
        self.assertEqual(storage[username]["lastName"], "Updated")

    def test_sync_removes_deleted_users_from_storage(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        storage = plugin._get_user_storage()
        storage["nonexistent_user_xyz"] = {
            "email": "ghost@example.com",
            "firstName": "Ghost",
            "lastName": "User",
        }
        transaction.commit()

        stats = sync_all_users()

        storage = plugin._get_user_storage()
        self.assertNotIn(
            "nonexistent_user_xyz",
            storage,
            "User not in Keycloak should be removed from storage",
        )
        self.assertGreater(
            stats["users_removed"], 0, "Should have removed at least one user"
        )

    def test_sync_returns_correct_stats(self):
        username = "test_usersync_stats_001"
        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email="test_usersync_stats_001@example.com",
            first_name="Stats",
            last_name="Test",
        )

        stats = sync_all_users()

        self.assertIn("users_synced", stats)
        self.assertIn("users_removed", stats)
        self.assertIn("errors", stats)
        self.assertGreater(
            stats["users_synced"], 0, "Should have synced at least one user"
        )
        self.assertEqual(stats["errors"], 0, "Should have no errors")


class TestSyncKeycloakUsersView(UserSyncTestBase):
    def test_sync_view_returns_error_when_not_enabled(self):
        response = requests.get(
            f"{self.portal_url}/@@sync-keycloak-users",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 400)

        data = response.json()
        self.assertFalse(data["success"])

    def test_sync_view_returns_json(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_users = True
        transaction.commit()

        response = requests.get(
            f"{self.portal_url}/@@sync-keycloak-users",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"], "Sync should succeed")
        self.assertIn("stats", data)
        self.assertIn("users_synced", data["stats"])

    def test_sync_view_syncs_users_successfully(self):
        username = "test_usersync_view_001"
        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email="test_usersync_view_001@example.com",
            first_name="View",
            last_name="Test",
        )

        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_users = True
        transaction.commit()

        response = requests.get(
            f"{self.portal_url}/@@sync-keycloak-users",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"])
        self.assertGreater(
            data["stats"]["users_synced"],
            0,
            "Should have synced at least one user",
        )

    def test_sync_view_returns_error_when_enumeration_active(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_users = True

        acl_users = api.portal.get_tool("acl_users")
        acl_users.plugins.activatePlugin(IUserEnumerationPlugin, "keycloak")
        transaction.commit()

        response = requests.get(
            f"{self.portal_url}/@@sync-keycloak-users",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 400)

        data = response.json()
        self.assertFalse(data["success"])


class TestGroupSyncViewIsGroupOnly(UserSyncTestBase):
    def test_group_sync_view_excludes_user_sync_stats(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        plugin.sync_users = True
        transaction.commit()

        response = requests.get(
            f"{self.portal_url}/@@sync-keycloak-groups",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"])
        self.assertNotIn(
            "users_synced",
            data["stats"],
            "Group sync view should not include user sync stats",
        )

    def test_group_sync_view_includes_cleanup_stats(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        transaction.commit()

        response = requests.get(
            f"{self.portal_url}/@@sync-keycloak-groups",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn(
            "users_cleaned",
            data["stats"],
            "Group sync view should include stale user cleanup stats",
        )


class TestSyncKeycloakView(UserSyncTestBase):
    def test_sync_all_view_returns_error_when_not_enabled(self):
        response = requests.get(
            f"{self.portal_url}/@@sync-keycloak",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 400)

        data = response.json()
        self.assertFalse(data["success"])

    def test_sync_all_view_returns_json(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        transaction.commit()

        response = requests.get(
            f"{self.portal_url}/@@sync-keycloak",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"], "Sync should succeed")
        self.assertIn("stats", data)
        self.assertIn("groups_created", data["stats"])
        self.assertIn("users_added", data["stats"])

    def test_sync_all_view_includes_user_sync_stats_when_enabled(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        plugin.sync_users = True
        transaction.commit()

        response = requests.get(
            f"{self.portal_url}/@@sync-keycloak",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn(
            "users_synced",
            data["stats"],
            "Sync-all response should include user sync stats when enabled",
        )

    def test_sync_all_view_excludes_user_sync_stats_when_disabled(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        plugin.sync_users = False
        transaction.commit()

        response = requests.get(
            f"{self.portal_url}/@@sync-keycloak",
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"])
        self.assertNotIn(
            "users_synced",
            data["stats"],
            "Sync-all response should not include user sync stats when disabled",
        )
        self.assertIn(
            "users_cleaned",
            data["stats"],
            "Sync-all response should always include cleanup stats",
        )
