"""REST API service for full Keycloak synchronization."""

from wcs.keycloak.restapi.base import BaseSyncService
from wcs.keycloak.sync_mixins import SyncKeycloakMixin


class SyncKeycloakService(SyncKeycloakMixin, BaseSyncService):
    """Service to perform a full Keycloak-to-Plone synchronization."""
