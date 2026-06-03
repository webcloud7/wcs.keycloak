"""Tests for UUID-keyed Keycloak group synchronization."""

from plone import api
from wcs.keycloak.sync import get_plone_group_id
from wcs.keycloak.sync import is_synced_group
from wcs.keycloak.sync import sync_all_groups
from wcs.keycloak.sync import sync_all_memberships
from wcs.keycloak.testing.mixins import KeycloakPluginTestMixin
from wcs.keycloak.tests import FunctionalTesting

import transaction


class TestKeycloakGroupSync(KeycloakPluginTestMixin, FunctionalTesting):
    def setUp(self):
        super().setUp()
        self.grant("Manager")
        self._setup_keycloak_client()
        self._create_service_account_client()
        self._setup_keycloak_plugin(
            activate_user_adder=True,
            activate_enumeration=True,
        )
        plugin = api.portal.get_tool("acl_users")["keycloak"]
        plugin.sync_groups = True
        transaction.commit()

    def tearDown(self):
        self._cleanup_keycloak_plugin()
        self._delete_service_account_client()
        self._teardown_keycloak_client()
        super().tearDown()

    def _create_kc_group(self, name):
        existing = self.client.get_group_by_name(name)
        if existing:
            self.client.delete_group(existing["id"])
        uuid = self.client.create_group(name)
        self._created_groups.append(uuid)
        return uuid

    def _rename_kc_group(self, group_uuid, new_name):
        url = f"{self.client._get_admin_url()}/groups/{group_uuid}"
        self.client._make_request("PUT", url, json={"name": new_name})

    def _synced_group_ids(self):
        portal_groups = api.portal.get_tool("portal_groups")
        return {gid for gid in portal_groups.listGroupIds() if is_synced_group(gid)}

    def test_sync_creates_uuid_keyed_group_with_name_as_title(self):
        kc_uuid = self._create_kc_group("sync-engineering")

        sync_all_groups()

        plone_group_id = get_plone_group_id(kc_uuid)
        plone_group = api.group.get(groupname=plone_group_id)
        self.assertIsNotNone(
            plone_group,
            f"Expected UUID-keyed Plone group {plone_group_id} to exist after sync",
        )
        self.assertEqual(
            "sync-engineering",
            plone_group.getProperty("title"),
            "Plone group title should hold the Keycloak group name",
        )
        self.assertEqual(
            f"keycloak_{kc_uuid}",
            plone_group_id,
            "Synced Plone group must be keyed on the Keycloak UUID",
        )

    def test_renaming_keycloak_group_preserves_plone_group_id_and_sharing(self):
        kc_uuid = self._create_kc_group("sync-marketing")
        sync_all_groups()

        plone_group_id = get_plone_group_id(kc_uuid)
        page = api.content.create(
            container=self.portal, type="Document", title="Shared Page"
        )
        page.manage_setLocalRoles(plone_group_id, ["Reader"])
        page.reindexObjectSecurity()
        transaction.commit()

        synced_before = self._synced_group_ids()

        self._rename_kc_group(kc_uuid, "sync-marketing-renamed")
        sync_all_groups()

        synced_after = self._synced_group_ids()
        self.assertEqual(
            synced_before,
            synced_after,
            "Renaming a Keycloak group must not add or delete any Plone group",
        )

        plone_group = api.group.get(groupname=plone_group_id)
        self.assertIsNotNone(
            plone_group,
            f"Plone group {plone_group_id} must survive a Keycloak rename",
        )
        self.assertEqual(
            "sync-marketing-renamed",
            plone_group.getProperty("title"),
            "Plone group title should be updated to the new Keycloak name",
        )
        self.assertIn(
            "Reader",
            page.get_local_roles_for_userid(plone_group_id),
            "Local-role assignment must be preserved across a Keycloak rename",
        )

    def test_membership_sync_uses_uuid_keyed_group(self):
        kc_uuid = self._create_kc_group("sync-members")
        username = "sync-member@example.com"
        self._create_keycloak_test_user(username, username, "Sync Member")

        user_id = self.client.get_user_id_by_username(username)
        self.client.add_user_to_group(user_id, kc_uuid)

        sync_all_groups()
        sync_all_memberships()

        plone_group_id = get_plone_group_id(kc_uuid)
        plone_group = api.group.get(groupname=plone_group_id)
        self.assertIn(
            username,
            plone_group.getGroupMemberIds(),
            f"{username} should be a member of UUID-keyed group {plone_group_id}",
        )
