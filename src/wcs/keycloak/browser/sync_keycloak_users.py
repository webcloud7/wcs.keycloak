"""Browser view for Keycloak user synchronization."""
from wcs.keycloak.browser.base import BaseSyncView
from wcs.keycloak.user_sync import is_user_sync_enabled
from wcs.keycloak.user_sync import sync_all_users


class SyncKeycloakUsersView(BaseSyncView):
    """View to sync Keycloak users to the plugin's local storage."""

    disabled_message = 'Keycloak user sync is not enabled'

    def is_enabled(self):
        return is_user_sync_enabled()

    def run_sync(self):
        return sync_all_users()

    def build_message(self, stats):
        return (
            f"User sync complete: {stats['users_synced']} users synced, "
            f"{stats['users_removed']} removed."
        )
