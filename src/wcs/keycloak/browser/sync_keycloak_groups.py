"""Browser view for Keycloak group synchronization."""

from wcs.keycloak.browser.base import BaseSyncView
from wcs.keycloak.sync import is_group_sync_enabled
from wcs.keycloak.sync import sync_groups_and_memberships


class SyncKeycloakGroupsView(BaseSyncView):
    """View to sync Keycloak groups and memberships to Plone."""

    disabled_message = "Keycloak group sync is not enabled"

    def is_enabled(self):
        return is_group_sync_enabled()

    def run_sync(self):
        return sync_groups_and_memberships()

    def build_message(self, stats):
        return (
            f"Sync complete: {stats['groups_created']} groups created, "
            f"{stats['groups_updated']} updated, {stats['groups_deleted']} deleted. "
            f"{stats['users_added']} users added to groups, "
            f"{stats['users_removed']} removed. "
            f"{stats['users_cleaned']} stale users cleaned up."
        )
