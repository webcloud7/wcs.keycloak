"""REST API service for Keycloak group synchronization."""

from wcs.keycloak.restapi.base import BaseSyncService
from wcs.keycloak.sync_mixins import SyncKeycloakGroupsMixin


class SyncKeycloakGroupsService(SyncKeycloakGroupsMixin, BaseSyncService):
    """Service to sync Keycloak groups and memberships to Plone."""
