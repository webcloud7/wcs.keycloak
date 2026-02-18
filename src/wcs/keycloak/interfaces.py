"""Zope interfaces for wcs.keycloak."""

from zope.interface import Interface
from zope.publisher.interfaces.browser import IDefaultBrowserLayer


class IKeycloakLayer(IDefaultBrowserLayer):
    """Browser layer marker interface for wcs.keycloak."""


class IKeycloakPlugin(Interface):
    """Marker interface for the Keycloak PAS plugin."""
