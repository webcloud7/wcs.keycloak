"""Browser view for full Keycloak synchronization."""
from wcs.keycloak.browser.base import BaseSyncView
from wcs.keycloak.sync import is_group_sync_enabled
from wcs.keycloak.sync import sync_all


class SyncKeycloakView(BaseSyncView):
    """View to perform a full Keycloak-to-Plone synchronization.

    This view performs a complete synchronization of:
    1. All groups from Keycloak (creates, updates, deletes Plone groups)
    2. All group memberships (adds/removes users from groups)
    3. All users (when user sync is enabled)
    4. Cleanup of deleted users from local storage

    For group-only sync, use @@sync-keycloak-groups instead.
    For user-only sync, use @@sync-keycloak-users instead.

    Requires Manager role to execute.

    Usage:
        - Manual: Visit @@sync-keycloak in browser
        - Cron: curl -u admin:password http://site/@@sync-keycloak
    """

    disabled_message = 'Keycloak group sync is not enabled'

    def is_enabled(self):
        return is_group_sync_enabled()

    def run_sync(self):
        return sync_all()

    def build_message(self, stats):
        message = (
            f"Sync complete: {stats['groups_created']} groups created, "
            f"{stats['groups_updated']} updated, {stats['groups_deleted']} deleted. "
            f"{stats['users_added']} users added to groups, "
            f"{stats['users_removed']} removed."
        )

        if 'users_synced' in stats:
            message += (
                f" User sync: {stats['users_synced']} synced, "
                f"{stats['users_sync_removed']} removed."
            )

        return message
