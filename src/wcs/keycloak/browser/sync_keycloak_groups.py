"""Browser view for Keycloak group synchronization."""
from plone.protect.interfaces import IDisableCSRFProtection
from Products.Five.browser import BrowserView
from wcs.keycloak.sync import is_group_sync_enabled
from wcs.keycloak.sync import sync_groups_and_memberships
from zope.interface import alsoProvides
import json


class SyncKeycloakGroupsView(BrowserView):
    """View to sync Keycloak groups and memberships to Plone.

    This view performs a full synchronization of:
    1. All groups from Keycloak (creates, updates, deletes Plone groups)
    2. All group memberships (adds/removes users from groups)

    Requires Manager role to execute.

    Usage:
        - Manual: Visit @@sync-keycloak-groups in browser
        - Cron: curl -u admin:password http://site/@@sync-keycloak-groups
    """

    def __call__(self):
        """Execute the sync operation.

        Returns:
            JSON response with sync statistics or error message.
        """
        alsoProvides(self.request, IDisableCSRFProtection)

        self.request.response.setHeader('Content-Type', 'application/json')

        if not is_group_sync_enabled():
            self.request.response.setStatus(400)
            return json.dumps({
                'success': False,
                'message': 'Keycloak group sync is not enabled',
            })

        try:
            stats = sync_groups_and_memberships()

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

            if stats['errors'] > 0:
                message += f" {stats['errors']} errors occurred."

            return json.dumps({
                'success': True,
                'message': message,
                'stats': stats,
            })

        except Exception as e:
            self.request.response.setStatus(500)
            return json.dumps({
                'success': False,
                'message': f'Sync failed: {str(e)}',
            })
