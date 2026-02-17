"""Interfaces for wcs.keycloak.

This module defines the Zope interfaces used by the wcs.keycloak package
for component registration and marker interfaces.

Interfaces:
    IKeycloakLayer: Browser layer marker for view registration
    IKeycloakPlugin: Marker interface for the PAS plugin

The IKeycloakLayer is registered when the package is installed and can be
used to register browser views specific to wcs.keycloak.

The IKeycloakPlugin interface is used to identify the Keycloak plugin
instance within acl_users and is implemented by KeycloakPlugin.
"""
from zope.interface import Interface
from zope.publisher.interfaces.browser import IDefaultBrowserLayer


class IKeycloakLayer(IDefaultBrowserLayer):
    """Browser layer marker interface for wcs.keycloak.

    This interface is registered as the browser layer when wcs.keycloak
    is installed. It can be used to register browser views that should
    only be available when this package is active.

    The layer is automatically applied to requests when the wcs.keycloak
    profile is installed in a Plone site.
    """


class IKeycloakPlugin(Interface):
    """Marker interface for the Keycloak PAS plugin.

    This interface identifies the KeycloakPlugin instance within acl_users.
    It is used by helper functions to locate the plugin for configuration
    access and client creation.

    The interface is implemented by KeycloakPlugin and is used in:
        - get_keycloak_plugin(): To find the plugin in acl_users
        - Group sync: To check if Keycloak integration is enabled

    Example:
        To check if an object is a Keycloak plugin::

            from wcs.keycloak.interfaces import IKeycloakPlugin

            if IKeycloakPlugin.providedBy(plugin):
                # This is the Keycloak plugin
                server_url = plugin.server_url
    """
