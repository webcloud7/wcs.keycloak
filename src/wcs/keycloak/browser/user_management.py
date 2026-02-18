from plone import api
from Products.CMFPlone.controlpanel.browser.usergroups_groupsoverview import (
    GroupsOverviewControlPanel,
)
from Products.CMFPlone.controlpanel.browser.usergroups_usersoverview import (
    UsersOverviewControlPanel,
)
from wcs.keycloak.client import get_keycloak_plugin
from wcs.keycloak.sync import is_group_sync_enabled
from wcs.keycloak.sync import sync_groups_and_memberships
from wcs.keycloak.user_sync import is_user_sync_enabled
from wcs.keycloak.user_sync import sync_all_users


SYNC_STAT_LABELS = [
    ("groups_created", "groups created"),
    ("groups_updated", "groups updated"),
    ("groups_deleted", "groups deleted"),
    ("users_added", "memberships added"),
    ("users_removed", "memberships removed"),
    ("users_cleaned", "stale users cleaned"),
    ("users_synced", "users synced"),
    ("errors", "errors"),
]


class KeycloakPluginMixin:
    def is_keycloak_configured(self):
        plugin = get_keycloak_plugin()
        if not plugin:
            return False
        return bool(plugin.server_url and plugin.realm)

    def is_controls_enabled(self):
        return api.portal.get_registry_record(
            "wcs.keycloak.show_keycloak_controls",
            default=False,
        )

    def show_keycloak_controls(self):
        return self.is_keycloak_configured() and self.is_controls_enabled()

    def _get_keycloak_admin_url(self, section):
        plugin = get_keycloak_plugin()
        if not plugin:
            return ""
        server_url = plugin.server_url.rstrip("/")
        realm = plugin.realm
        return f"{server_url}/admin/{realm}/console/#/{realm}/{section}"

    def _build_sync_message(self, stats):
        messages = [
            f"{stats[key]} {label}" for key, label in SYNC_STAT_LABELS if stats.get(key)
        ]
        if messages:
            return "Keycloak sync completed: " + ", ".join(messages) + "."
        return "Keycloak sync completed: no changes."


class KeycloakUsersOverviewControlPanel(KeycloakPluginMixin, UsersOverviewControlPanel):
    def __call__(self):
        form = self.request.form
        if form.get("form.button.SyncUsers") is not None:
            self._handle_sync_users()

        return super().__call__()

    def _handle_sync_users(self):
        stats = sync_all_users()
        message = self._build_sync_message(stats)
        api.portal.show_message(message, self.request, type="info")

    def is_user_sync_enabled(self):
        return is_user_sync_enabled()

    def get_keycloak_users_url(self):
        return self._get_keycloak_admin_url("users")


class KeycloakGroupsOverviewControlPanel(
    KeycloakPluginMixin, GroupsOverviewControlPanel
):
    def __call__(self):
        form = self.request.form
        if form.get("form.button.SyncGroups") is not None:
            self._handle_sync_groups()

        return super().__call__()

    def _handle_sync_groups(self):
        stats = sync_groups_and_memberships()
        message = self._build_sync_message(stats)
        api.portal.show_message(message, self.request, type="info")

    def is_group_sync_enabled(self):
        return is_group_sync_enabled()

    def get_keycloak_groups_url(self):
        return self._get_keycloak_admin_url("groups")
