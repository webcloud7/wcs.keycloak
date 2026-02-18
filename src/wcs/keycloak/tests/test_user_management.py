"""Tests for Keycloak user/group management control panel overrides."""
from bs4 import BeautifulSoup
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

    def _get_soup(self, path):
        response = requests.get(
            f'{self.portal_url}/{path}',
            auth=self.credentials,
        )
        self.assertEqual(response.status_code, 200)
        return BeautifulSoup(response.text, 'html.parser')


class TestUsersOverviewKeycloakControls(UserManagementTestBase):

    def test_add_user_button_links_to_keycloak_when_controls_enabled(self):
        self._set_registry_controls(True)
        soup = self._get_soup('@@usergroup-userprefs')

        button = soup.select_one('#add-user')
        expected_url = (
            f'{KEYCLOAK_SERVER_URL}/admin/{KEYCLOAK_REALM}'
            f'/console/#/{KEYCLOAK_REALM}/users'
        )
        self.assertEqual(button['href'], expected_url)
        self.assertEqual(button.get('target'), '_blank')
        self.assertNotIn('pat-plone-modal', button.get('class', []))

    def test_add_user_button_uses_plone_modal_when_controls_disabled(self):
        self._set_registry_controls(False)
        soup = self._get_soup('@@usergroup-userprefs')

        button = soup.select_one('#add-user')
        self.assertIn('pat-plone-modal', button['class'])
        self.assertTrue(
            button['href'].endswith('@@new-user'),
            'Add user button should link to @@new-user',
        )

    def test_sync_users_button_shown_when_user_sync_enabled(self):
        self._set_registry_controls(True)
        plugin = api.portal.get_tool('acl_users')['keycloak']
        plugin.sync_users = True
        transaction.commit()

        soup = self._get_soup('@@usergroup-userprefs')

        alert = soup.select_one('.alert.alert-info strong')
        self.assertEqual(alert.text, 'Keycloak User Sync')

        sync_button = soup.select_one('button[name="form.button.SyncUsers"]')
        self.assertIsNotNone(sync_button)
        self.assertEqual(sync_button.text, 'Sync Now')

    def test_sync_users_button_hidden_when_user_sync_disabled(self):
        self._set_registry_controls(True)
        soup = self._get_soup('@@usergroup-userprefs')

        sync_button = soup.select_one('button[name="form.button.SyncUsers"]')
        self.assertIsNone(sync_button)

    def test_sync_users_button_hidden_when_controls_disabled(self):
        self._set_registry_controls(False)
        plugin = api.portal.get_tool('acl_users')['keycloak']
        plugin.sync_users = True
        transaction.commit()

        soup = self._get_soup('@@usergroup-userprefs')

        sync_button = soup.select_one('button[name="form.button.SyncUsers"]')
        self.assertIsNone(sync_button)


class TestGroupsOverviewKeycloakControls(UserManagementTestBase):

    def test_add_group_button_links_to_keycloak_when_controls_enabled(self):
        self._set_registry_controls(True)
        soup = self._get_soup('@@usergroup-groupprefs')

        button = soup.select_one('#add-group')
        expected_url = (
            f'{KEYCLOAK_SERVER_URL}/admin/{KEYCLOAK_REALM}'
            f'/console/#/{KEYCLOAK_REALM}/groups'
        )
        self.assertEqual(button['href'], expected_url)
        self.assertEqual(button.get('target'), '_blank')
        self.assertNotIn('pat-plone-modal', button.get('class', []))

    def test_add_group_button_uses_plone_modal_when_controls_disabled(self):
        self._set_registry_controls(False)
        soup = self._get_soup('@@usergroup-groupprefs')

        button = soup.select_one('#add-group')
        self.assertIn('pat-plone-modal', button['class'])
        self.assertTrue(
            button['href'].endswith('@@usergroup-groupdetails'),
            'Add group button should link to @@usergroup-groupdetails',
        )

    def test_sync_groups_button_shown_when_group_sync_enabled(self):
        self._set_registry_controls(True)
        plugin = api.portal.get_tool('acl_users')['keycloak']
        plugin.sync_groups = True
        transaction.commit()

        soup = self._get_soup('@@usergroup-groupprefs')

        alert = soup.select_one('.alert.alert-info strong')
        self.assertEqual(alert.text, 'Keycloak Group Sync')

        sync_button = soup.select_one('button[name="form.button.SyncGroups"]')
        self.assertIsNotNone(sync_button)
        self.assertEqual(sync_button.text, 'Sync Now')

    def test_sync_groups_button_hidden_when_group_sync_disabled(self):
        self._set_registry_controls(True)
        soup = self._get_soup('@@usergroup-groupprefs')

        sync_button = soup.select_one('button[name="form.button.SyncGroups"]')
        self.assertIsNone(sync_button)

    def test_sync_groups_button_hidden_when_controls_disabled(self):
        self._set_registry_controls(False)
        plugin = api.portal.get_tool('acl_users')['keycloak']
        plugin.sync_groups = True
        transaction.commit()

        soup = self._get_soup('@@usergroup-groupprefs')

        sync_button = soup.select_one('button[name="form.button.SyncGroups"]')
        self.assertIsNone(sync_button)
