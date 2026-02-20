"""Browser view for full Keycloak synchronization."""

from wcs.keycloak.browser.base import BaseSyncView
from wcs.keycloak.sync_mixins import SyncKeycloakMixin


class SyncKeycloakView(SyncKeycloakMixin, BaseSyncView):
    """View to perform a full Keycloak-to-Plone synchronization."""
