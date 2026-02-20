"""REST API service for Keycloak user synchronization."""

from wcs.keycloak.restapi.base import BaseSyncService
from wcs.keycloak.sync_mixins import SyncKeycloakUsersMixin


class SyncKeycloakUsersService(SyncKeycloakUsersMixin, BaseSyncService):
    """Service to sync Keycloak users to the plugin's local storage."""
