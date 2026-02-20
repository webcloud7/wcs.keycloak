"""Browser view for Keycloak group synchronization."""

from wcs.keycloak.browser.base import BaseSyncView
from wcs.keycloak.sync_mixins import SyncKeycloakGroupsMixin


class SyncKeycloakGroupsView(SyncKeycloakGroupsMixin, BaseSyncView):
    """View to sync Keycloak groups and memberships to Plone."""
