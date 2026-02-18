"""Keycloak user synchronization to Plone's plugin storage.

This module provides functions to sync Keycloak users to the KeycloakPlugin's
_user_storage (OOBTree). Keycloak is the single source of truth - users are
synced one-way from Keycloak to the plugin storage.

Sync Operations:
    - sync_all_users(): Fetches all users from Keycloak and stores them in
      _user_storage, removing users that no longer exist in Keycloak.

Triggers:
    - Manual: @@sync-keycloak-users browser view
    - Combined: Also triggered by @@sync-keycloak when sync_users is enabled
"""
from wcs.keycloak.client import get_client_and_plugin
from wcs.keycloak.client import is_sync_enabled
from wcs.keycloak.plugin import extract_user_storage_data
import logging


logger = logging.getLogger(__name__)

# Maximum results to fetch from Keycloak during user sync
MAX_SYNC_USERS = 10000


def is_user_sync_enabled():
    """Check if Keycloak user sync is enabled.

    Returns:
        True if Keycloak is configured and user sync is enabled, False otherwise.
    """
    return is_sync_enabled('sync_users')


def _remove_stale_users(user_storage, keycloak_usernames):
    """Remove users from storage that no longer exist in Keycloak.

    Args:
        user_storage: The plugin's OOBTree user storage.
        keycloak_usernames: Set of usernames currently in Keycloak.

    Returns:
        Dict with removal statistics: users_removed, errors.
    """
    stats = {'users_removed': 0, 'errors': 0}

    stored_usernames = set(user_storage.keys())
    users_to_remove = stored_usernames - keycloak_usernames

    for username in users_to_remove:
        try:
            del user_storage[username]
            stats['users_removed'] += 1
            logger.info(f"Removed deleted user from storage: {username}")
        except Exception as e:
            logger.error(f"Error removing user {username} from storage: {e}")
            stats['errors'] += 1

    return stats


def cleanup_deleted_users():
    """Remove users from _user_storage that no longer exist in Keycloak.

    Fetches all usernames from Keycloak and compares them with usernames
    stored in the KeycloakPlugin's _user_storage. Users that exist in
    storage but not in Keycloak are removed.

    Returns:
        Dict with cleanup statistics: users_cleaned, errors.
    """
    stats = {'users_cleaned': 0, 'errors': 0}

    client, plugin = get_client_and_plugin('user cleanup')
    if not client:
        return stats

    try:
        keycloak_users = client.search_users(max_results=MAX_SYNC_USERS)
        keycloak_usernames = {
            user.get('username') for user in keycloak_users if user.get('username')
        }

        user_storage = plugin._get_user_storage()
        removal_stats = _remove_stale_users(user_storage, keycloak_usernames)

        stats['users_cleaned'] = removal_stats['users_removed']
        stats['errors'] = removal_stats['errors']

        logger.info(
            f"User cleanup complete: {stats['users_cleaned']} users removed, "
            f"{stats['errors']} errors"
        )

    except Exception as e:
        logger.error(f"Error during user cleanup: {e}")
        stats['errors'] += 1

    return stats


def sync_all_users():
    """Sync all users from Keycloak to the plugin's _user_storage.

    Fetches all users from Keycloak, stores/updates their data in
    _user_storage, and removes users that no longer exist in Keycloak.

    Returns:
        Dict with sync statistics: users_synced, users_removed, errors.
    """
    stats = {'users_synced': 0, 'users_removed': 0, 'errors': 0}

    client, plugin = get_client_and_plugin('user sync')
    if not client:
        return stats

    try:
        keycloak_users = client.search_users(max_results=MAX_SYNC_USERS)
        keycloak_usernames = set()

        user_storage = plugin._get_user_storage()

        for user in keycloak_users:
            username = user.get('username', '')
            if not username:
                continue

            keycloak_usernames.add(username)

            try:
                user_storage[username] = extract_user_storage_data(user)
                stats['users_synced'] += 1
            except Exception as e:
                logger.error(f"Error syncing user {username}: {e}")
                stats['errors'] += 1

        # Remove users from storage that no longer exist in Keycloak
        removal_stats = _remove_stale_users(user_storage, keycloak_usernames)
        stats['users_removed'] = removal_stats['users_removed']
        stats['errors'] += removal_stats['errors']

        logger.info(
            f"User sync complete: {stats['users_synced']} synced, "
            f"{stats['users_removed']} removed, {stats['errors']} errors"
        )

    except Exception as e:
        logger.error(f"Error during user sync: {e}")
        stats['errors'] += 1

    return stats
