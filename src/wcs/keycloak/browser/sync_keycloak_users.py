"""Browser view for Keycloak user synchronization."""

from wcs.keycloak.browser.base import BaseSyncView
from wcs.keycloak.sync_mixins import SyncKeycloakUsersMixin


class SyncKeycloakUsersView(SyncKeycloakUsersMixin, BaseSyncView):
    """View to sync Keycloak users to the plugin's local storage."""
