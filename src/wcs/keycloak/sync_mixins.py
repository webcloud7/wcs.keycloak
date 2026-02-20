"""Shared mixins for Keycloak sync views and REST API services."""

from wcs.keycloak.sync import is_group_sync_enabled
from wcs.keycloak.sync import sync_all
from wcs.keycloak.sync import sync_groups_and_memberships
from wcs.keycloak.user_sync import is_user_sync_enabled
from wcs.keycloak.user_sync import sync_all_users


class SyncKeycloakMixin:
    """Shared logic for full Keycloak synchronization."""

    disabled_message = "Keycloak group sync is not enabled"

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

        if "users_synced" in stats:
            message += (
                f" User sync: {stats['users_synced']} synced, "
                f"{stats['users_sync_removed']} removed."
            )

        return message


class SyncKeycloakGroupsMixin:
    """Shared logic for Keycloak group synchronization."""

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


class SyncKeycloakUsersMixin:
    """Shared logic for Keycloak user synchronization."""

    disabled_message = "Keycloak user sync is not enabled"

    def is_enabled(self):
        return is_user_sync_enabled()

    def run_sync(self):
        return sync_all_users()

    def build_message(self, stats):
        return (
            f"User sync complete: {stats['users_synced']} users synced, "
            f"{stats['users_removed']} removed."
        )
