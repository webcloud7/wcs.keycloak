"""Tests for Keycloak sync REST API endpoints."""

from plone import api
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from wcs.keycloak.tests.test_user_sync import UserSyncTestBase

import requests
import transaction


class TestSyncKeycloakUsersService(UserSyncTestBase):
    def test_returns_error_when_not_enabled(self):
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak-users",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 400)

        data = response.json()
        self.assertFalse(data["success"], "Should fail when sync not enabled")

    def test_returns_json_on_success(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_users = True
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak-users",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"], "Sync should succeed")
        self.assertIn("stats", data)
        self.assertIn("users_synced", data["stats"])

    def test_syncs_users_successfully(self):
        username = "test_restapi_usersync_001"
        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email="test_restapi_usersync_001@example.com",
            first_name="RestApi",
            last_name="Test",
        )

        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_users = True
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak-users",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"], "Sync should succeed")
        self.assertGreater(
            data["stats"]["users_synced"],
            0,
            "Should have synced at least one user",
        )

    def test_returns_error_when_enumeration_active(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_users = True

        acl_users = api.portal.get_tool("acl_users")
        acl_users.plugins.activatePlugin(IUserEnumerationPlugin, "keycloak")
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak-users",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 400)

        data = response.json()
        self.assertFalse(data["success"], "Should fail when enumeration is active")


class TestSyncKeycloakGroupsService(UserSyncTestBase):
    def test_returns_error_when_not_enabled(self):
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak-groups",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 400)

        data = response.json()
        self.assertFalse(data["success"], "Should fail when sync not enabled")

    def test_excludes_user_sync_stats(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        plugin.sync_users = True
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak-groups",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"], "Sync should succeed")
        self.assertNotIn("users_synced", data["stats"])

    def test_includes_cleanup_stats(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak-groups",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"], "Sync should succeed")
        self.assertIn("users_cleaned", data["stats"])


class TestSyncKeycloakService(UserSyncTestBase):
    def test_returns_error_when_not_enabled(self):
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 400)

        data = response.json()
        self.assertFalse(data["success"], "Should fail when sync not enabled")

    def test_returns_json_on_success(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"], "Sync should succeed")
        self.assertIn("stats", data)
        self.assertIn("groups_created", data["stats"])
        self.assertIn("users_added", data["stats"])

    def test_includes_user_sync_stats_when_enabled(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        plugin.sync_users = True
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"], "Sync should succeed")
        self.assertIn("users_synced", data["stats"])

    def test_excludes_user_sync_stats_when_disabled(self):
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        plugin.sync_users = False
        transaction.commit()

        response = requests.post(
            f"{self.portal_url}/@sync-keycloak",
            auth=self.credentials,
            headers=self.api_post_headers,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data["success"], "Sync should succeed")
        self.assertNotIn("users_synced", data["stats"])
        self.assertIn("users_cleaned", data["stats"])
