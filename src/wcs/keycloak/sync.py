"""Keycloak group and membership synchronization to Plone."""
from plone import api
from wcs.keycloak.client import get_client_and_plugin
from wcs.keycloak.client import is_sync_enabled
from wcs.keycloak.user_sync import cleanup_deleted_users
from wcs.keycloak.user_sync import is_user_sync_enabled
from wcs.keycloak.user_sync import sync_all_users
import logging


logger = logging.getLogger(__name__)

# Prefix for synced groups to identify them as Keycloak-managed
KEYCLOAK_GROUP_PREFIX = 'keycloak_'

# Maximum results to fetch from Keycloak during group/membership sync
MAX_SYNC_GROUPS = 1000
MAX_SYNC_GROUP_MEMBERS = 1000


def is_group_sync_enabled():
    """Check if Keycloak group sync is enabled.

    Returns:
        True if Keycloak is configured and sync is enabled, False otherwise.
    """
    return is_sync_enabled('sync_groups')


def get_plone_group_id(keycloak_group_name):
    """Convert a Keycloak group name to a Plone group ID.

    Adds a prefix to distinguish Keycloak-synced groups from native Plone groups.

    Args:
        keycloak_group_name: The group name from Keycloak.

    Returns:
        The corresponding Plone group ID.
    """
    return f"{KEYCLOAK_GROUP_PREFIX}{keycloak_group_name}"


def get_keycloak_group_name(plone_group_id):
    """Extract the Keycloak group name from a Plone group ID.

    Args:
        plone_group_id: The Plone group ID.

    Returns:
        The Keycloak group name if this is a synced group, None otherwise.
    """
    if plone_group_id.startswith(KEYCLOAK_GROUP_PREFIX):
        return plone_group_id[len(KEYCLOAK_GROUP_PREFIX):]
    return None


def is_synced_group(plone_group_id):
    """Check if a Plone group is synced from Keycloak.

    Args:
        plone_group_id: The Plone group ID to check.

    Returns:
        True if the group is synced from Keycloak, False otherwise.
    """
    return plone_group_id.startswith(KEYCLOAK_GROUP_PREFIX)


def sync_all_groups():
    """Sync all groups from Keycloak to Plone.

    Creates new groups, updates existing ones, and removes groups that
    no longer exist in Keycloak.

    Returns:
        Dict with sync statistics: created, updated, deleted, errors.
    """
    stats = {'created': 0, 'updated': 0, 'deleted': 0, 'errors': 0}

    client, plugin = get_client_and_plugin('group sync')
    if not client:
        return stats

    try:
        # Fetch all groups from Keycloak
        keycloak_groups = client.search_groups(max_results=MAX_SYNC_GROUPS)
        keycloak_group_names = {g['name'] for g in keycloak_groups if g.get('name')}

        logger.info(f"Found {len(keycloak_group_names)} groups in Keycloak")

        # Get all existing synced Plone groups
        portal_groups = api.portal.get_tool('portal_groups')
        existing_plone_groups = portal_groups.listGroupIds()
        synced_plone_groups = {
            gid for gid in existing_plone_groups if is_synced_group(gid)
        }

        # Create or update groups from Keycloak
        for kc_group in keycloak_groups:
            group_name = kc_group.get('name')
            if not group_name:
                continue

            plone_group_id = get_plone_group_id(group_name)

            try:
                existing_group = api.group.get(groupname=plone_group_id)
                if existing_group:
                    # Group exists - update title if needed
                    current_title = existing_group.getProperty('title', '')
                    if current_title != group_name:
                        existing_group.setGroupProperties({'title': group_name})
                        stats['updated'] += 1
                        logger.debug(f"Updated group: {plone_group_id}")
                else:
                    # Create new group
                    api.group.create(
                        groupname=plone_group_id,
                        title=group_name,
                        description=f"Synced from Keycloak group: {group_name}",
                    )
                    stats['created'] += 1
                    logger.info(f"Created group: {plone_group_id}")

            except Exception as e:
                logger.error(f"Error syncing group {group_name}: {e}")
                stats['errors'] += 1

        # Remove groups that no longer exist in Keycloak
        expected_plone_ids = {
            get_plone_group_id(name) for name in keycloak_group_names
        }
        groups_to_delete = synced_plone_groups - expected_plone_ids

        for group_id in groups_to_delete:
            try:
                api.group.delete(groupname=group_id)
                stats['deleted'] += 1
                logger.info(f"Deleted group: {group_id}")
            except Exception as e:
                logger.error(f"Error deleting group {group_id}: {e}")
                stats['errors'] += 1

        logger.info(
            f"Group sync complete: created={stats['created']}, "
            f"updated={stats['updated']}, deleted={stats['deleted']}, "
            f"errors={stats['errors']}"
        )

    except Exception as e:
        logger.error(f"Error during group sync: {e}")
        stats['errors'] += 1

    return stats


def sync_all_memberships():
    """Sync all group memberships from Keycloak to Plone.

    For each synced Plone group, fetches the current members from Keycloak
    and updates the Plone group membership to match.

    Returns:
        Dict with sync statistics: users_added, users_removed, errors.
    """
    stats = {'users_added': 0, 'users_removed': 0, 'errors': 0}

    client, plugin = get_client_and_plugin('membership sync')
    if not client:
        return stats

    try:
        # Get all Keycloak groups
        keycloak_groups = client.search_groups(max_results=MAX_SYNC_GROUPS)

        for kc_group in keycloak_groups:
            group_name = kc_group.get('name')
            group_uuid = kc_group.get('id')
            if not group_name or not group_uuid:
                continue

            plone_group_id = get_plone_group_id(group_name)
            plone_group = api.group.get(groupname=plone_group_id)

            if not plone_group:
                # Group doesn't exist in Plone, skip
                continue

            try:
                # Get members from Keycloak
                kc_members = client.get_group_members(group_uuid, max_results=MAX_SYNC_GROUP_MEMBERS)
                kc_usernames = {
                    m.get('username') for m in kc_members if m.get('username')
                }

                # Get current Plone group members
                current_members = set(plone_group.getGroupMemberIds())

                # Add missing members
                to_add = kc_usernames - current_members
                for username in to_add:
                    try:
                        api.group.add_user(groupname=plone_group_id, username=username)
                        stats['users_added'] += 1
                        logger.debug(f"Added {username} to {plone_group_id}")
                    except Exception as e:
                        logger.warning(
                            f"Could not add {username} to {plone_group_id}: {e}"
                        )

                # Remove members no longer in Keycloak group
                to_remove = current_members - kc_usernames
                for username in to_remove:
                    try:
                        api.group.remove_user(groupname=plone_group_id, username=username)
                        stats['users_removed'] += 1
                        logger.debug(f"Removed {username} from {plone_group_id}")
                    except Exception as e:
                        logger.warning(
                            f"Could not remove {username} from {plone_group_id}: {e}"
                        )

            except Exception as e:
                logger.error(f"Error syncing membership for {plone_group_id}: {e}")
                stats['errors'] += 1

        logger.info(
            f"Membership sync complete: added={stats['users_added']}, "
            f"removed={stats['users_removed']}, errors={stats['errors']}"
        )

    except Exception as e:
        logger.error(f"Error during membership sync: {e}")
        stats['errors'] += 1

    return stats


def sync_user_memberships(username):
    """Sync a single user's group memberships from Keycloak to Plone.

    Args:
        username: The username to sync memberships for.

    Returns:
        Dict with sync statistics: groups_added, groups_removed, errors.
    """
    stats = {'groups_added': 0, 'groups_removed': 0, 'errors': 0}

    client, plugin = get_client_and_plugin('user membership sync')
    if not client:
        return stats

    try:
        # Get the Keycloak user ID
        user_id = client.get_user_id_by_username(username)
        if not user_id:
            logger.debug(f"User {username} not found in Keycloak")
            return stats

        # Get groups the user belongs to in Keycloak
        kc_groups = client.get_groups_for_user(user_id)
        kc_group_names = {g.get('name') for g in kc_groups if g.get('name')}
        expected_plone_groups = {get_plone_group_id(name) for name in kc_group_names}

        # Get current Plone group memberships (only synced groups)
        portal_groups = api.portal.get_tool('portal_groups')
        all_groups = portal_groups.listGroupIds()
        current_synced_memberships = set()

        for group_id in all_groups:
            if not is_synced_group(group_id):
                continue
            group = api.group.get(groupname=group_id)
            if group and username in group.getGroupMemberIds():
                current_synced_memberships.add(group_id)

        # Add user to missing groups
        to_add = expected_plone_groups - current_synced_memberships
        for group_id in to_add:
            # Only add if the group exists in Plone
            if api.group.get(groupname=group_id):
                try:
                    api.group.add_user(groupname=group_id, username=username)
                    stats['groups_added'] += 1
                    logger.debug(f"Added {username} to {group_id}")
                except Exception as e:
                    logger.warning(f"Could not add {username} to {group_id}: {e}")
                    stats['errors'] += 1

        # Remove user from groups they're no longer a member of in Keycloak
        to_remove = current_synced_memberships - expected_plone_groups
        for group_id in to_remove:
            try:
                api.group.remove_user(groupname=group_id, username=username)
                stats['groups_removed'] += 1
                logger.debug(f"Removed {username} from {group_id}")
            except Exception as e:
                logger.warning(f"Could not remove {username} from {group_id}: {e}")
                stats['errors'] += 1

        logger.info(
            f"User {username} membership sync: added={stats['groups_added']}, "
            f"removed={stats['groups_removed']}, errors={stats['errors']}"
        )

    except Exception as e:
        logger.error(f"Error syncing memberships for user {username}: {e}")
        stats['errors'] += 1

    return stats


def sync_groups_and_memberships():
    """Perform a sync of groups, memberships, and stale user cleanup.

    This is the entry point for the @@sync-keycloak-groups view. It:
    1. Syncs all groups from Keycloak (create/update/delete)
    2. Syncs all memberships for all groups
    3. Cleans up users from local storage that no longer exist in Keycloak

    Returns:
        Dict with combined statistics from all operations.
    """
    group_stats = sync_all_groups()
    membership_stats = sync_all_memberships()
    cleanup_stats = cleanup_deleted_users()

    return {
        'groups_created': group_stats['created'],
        'groups_updated': group_stats['updated'],
        'groups_deleted': group_stats['deleted'],
        'users_added': membership_stats['users_added'],
        'users_removed': membership_stats['users_removed'],
        'users_cleaned': cleanup_stats['users_cleaned'],
        'errors': (
            group_stats['errors']
            + membership_stats['errors']
            + cleanup_stats['errors']
        ),
    }


def sync_all():
    """Perform a full sync of groups, memberships, and users.

    This is the entry point for the @@sync-keycloak view. It:
    1. Syncs all groups from Keycloak (create/update/delete)
    2. Syncs all memberships for all groups
    3. Cleans up stale users from local storage
    4. Runs full user sync when sync_users is enabled

    Returns:
        Dict with combined statistics from all operations.
    """
    result = sync_groups_and_memberships()

    if is_user_sync_enabled():
        user_sync_stats = sync_all_users()
        result['users_synced'] = user_sync_stats['users_synced']
        result['users_sync_removed'] = user_sync_stats['users_removed']
        result['errors'] += user_sync_stats['errors']

    return result


def on_user_logged_in(event):
    """Event handler for user login.

    Syncs all groups from Keycloak, then syncs the logged-in user's
    group memberships.

    Args:
        event: The IUserLoggedInEvent containing the logged-in user.
    """
    if not is_group_sync_enabled():
        return

    username = event.object.getId()
    logger.info(f"User {username} logged in, syncing Keycloak groups")

    # First sync all groups (so they exist before adding user)
    sync_all_groups()

    # Then sync this user's memberships
    sync_user_memberships(username)
