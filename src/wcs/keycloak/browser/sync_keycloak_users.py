"""Browser view for Keycloak user synchronization."""
from wcs.keycloak.browser.base import BaseSyncView
from wcs.keycloak.user_sync import is_user_sync_enabled
from wcs.keycloak.user_sync import sync_all_users


class SyncKeycloakUsersView(BaseSyncView):
    """View to sync Keycloak users to the plugin's local storage.

    This view performs a full synchronization of all users from Keycloak
    to the KeycloakPlugin's _user_storage, including cleanup of deleted users.

    Requires Manager role to execute.

    Usage:
        - Manual: Visit @@sync-keycloak-users in browser
        - Cron: curl -u admin:password http://site/@@sync-keycloak-users
    """

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
