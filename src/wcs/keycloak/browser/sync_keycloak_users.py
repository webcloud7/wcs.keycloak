"""Browser view for Keycloak user synchronization."""
from plone.protect.interfaces import IDisableCSRFProtection
from Products.Five.browser import BrowserView
from wcs.keycloak.user_sync import is_user_sync_enabled
from wcs.keycloak.user_sync import sync_all_users
from zope.interface import alsoProvides
import json


class SyncKeycloakUsersView(BrowserView):
    """View to sync Keycloak users to the plugin's local storage.

    This view performs a full synchronization of all users from Keycloak
    to the KeycloakPlugin's _user_storage, including cleanup of deleted users.

    Requires Manager role to execute.

    Usage:
        - Manual: Visit @@sync-keycloak-users in browser
        - Cron: curl -u admin:password http://site/@@sync-keycloak-users
    """

    def __call__(self):
        """Execute the user sync operation.

        Returns:
            JSON response with sync statistics or error message.
        """
        alsoProvides(self.request, IDisableCSRFProtection)

        self.request.response.setHeader('Content-Type', 'application/json')

        if not is_user_sync_enabled():
            self.request.response.setStatus(400)
            return json.dumps({
                'success': False,
                'message': 'Keycloak user sync is not enabled',
            })

        try:
            stats = sync_all_users()

            message = (
                f"User sync complete: {stats['users_synced']} users synced, "
                f"{stats['users_removed']} removed."
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
                'message': f'User sync failed: {str(e)}',
            })
