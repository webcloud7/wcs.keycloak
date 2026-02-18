"""Tests for Keycloak user/group management control panel overrides."""
from plone import api
from wcs.keycloak.testing.mixins import KeycloakPluginTestMixin
from wcs.keycloak.testing.mixins import KEYCLOAK_REALM
from wcs.keycloak.testing.mixins import KEYCLOAK_SERVER_URL
from wcs.keycloak.tests import FunctionalTesting
import requests
import transaction


class UserManagementTestBase(KeycloakPluginTestMixin, FunctionalTesting):

    def setUp(self):
        super().setUp()
        self.grant('Manager')
        self._setup_keycloak_client()
        self._create_service_account_client()
        self._setup_keycloak_plugin(
            activate_user_adder=True,
            activate_enumeration=True,
        )

    def tearDown(self):
        self._cleanup_keycloak_plugin()
        self._delete_service_account_client()
        self._teardown_keycloak_client()
        super().tearDown()

    def _set_registry_controls(self, enabled):
        api.portal.set_registry_record(
            'wcs.keycloak.show_keycloak_controls', enabled,
        )
        transaction.commit()


class TestUsersOverviewKeycloakControls(UserManagementTestBase):

    def test_add_user_button_links_to_keycloak_when_controls_enabled(self):
        self._set_registry_controls(True)

        response = requests.get(
            f'{self.portal_url}/@@usergroup-userprefs',
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        expected_url = (
            f'{KEYCLOAK_SERVER_URL}/admin/{KEYCLOAK_REALM}'
            f'/console/#/{KEYCLOAK_REALM}/users'
        )
        self.assertIn(expected_url, response.text)

    def test_add_user_button_uses_plone_modal_when_controls_disabled(self):
        self._set_registry_controls(False)

        response = requests.get(
            f'{self.portal_url}/@@usergroup-userprefs',
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('pat-plone-modal', response.text)
        self.assertIn('@@new-user', response.text)

    def test_sync_users_button_shown_when_user_sync_enabled(self):
        self._set_registry_controls(True)
        plugin = api.portal.get_tool('acl_users')['keycloak']
        plugin.sync_users = True
        transaction.commit()

        response = requests.get(
            f'{self.portal_url}/@@usergroup-userprefs',
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('form.button.SyncUsers', response.text)
        self.assertIn('Keycloak User Sync', response.text)

    def test_sync_users_button_hidden_when_user_sync_disabled(self):
        self._set_registry_controls(True)

        response = requests.get(
            f'{self.portal_url}/@@usergroup-userprefs',
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('form.button.SyncUsers', response.text)

    def test_sync_users_button_hidden_when_controls_disabled(self):
        self._set_registry_controls(False)
        plugin = api.portal.get_tool('acl_users')['keycloak']
        plugin.sync_users = True
        transaction.commit()

        response = requests.get(
            f'{self.portal_url}/@@usergroup-userprefs',
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('form.button.SyncUsers', response.text)


class TestGroupsOverviewKeycloakControls(UserManagementTestBase):

    def test_add_group_button_links_to_keycloak_when_controls_enabled(self):
        self._set_registry_controls(True)

        response = requests.get(
            f'{self.portal_url}/@@usergroup-groupprefs',
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)

        expected_url = (
            f'{KEYCLOAK_SERVER_URL}/admin/{KEYCLOAK_REALM}'
            f'/console/#/{KEYCLOAK_REALM}/groups'
        )
        self.assertIn(expected_url, response.text)

    def test_add_group_button_uses_plone_modal_when_controls_disabled(self):
        self._set_registry_controls(False)

        response = requests.get(
            f'{self.portal_url}/@@usergroup-groupprefs',
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('pat-plone-modal', response.text)
        self.assertIn('@@usergroup-groupdetails', response.text)

    def test_sync_groups_button_shown_when_group_sync_enabled(self):
        self._set_registry_controls(True)
        plugin = api.portal.get_tool('acl_users')['keycloak']
        plugin.sync_groups = True
        transaction.commit()

        response = requests.get(
            f'{self.portal_url}/@@usergroup-groupprefs',
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn('form.button.SyncGroups', response.text)
        self.assertIn('Keycloak Group Sync', response.text)

    def test_sync_groups_button_hidden_when_group_sync_disabled(self):
        self._set_registry_controls(True)

        response = requests.get(
            f'{self.portal_url}/@@usergroup-groupprefs',
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('form.button.SyncGroups', response.text)

    def test_sync_groups_button_hidden_when_controls_disabled(self):
        self._set_registry_controls(False)
        plugin = api.portal.get_tool('acl_users')['keycloak']
        plugin.sync_groups = True
        transaction.commit()

        response = requests.get(
            f'{self.portal_url}/@@usergroup-groupprefs',
            auth=self.credentials,
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn('form.button.SyncGroups', response.text)
