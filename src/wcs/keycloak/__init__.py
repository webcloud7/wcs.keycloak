"""Keycloak integration for Plone 6.

This package provides a PAS (Pluggable Authentication Service) plugin for
integrating Plone with Keycloak identity management. It enables centralized
user management with Keycloak as the authoritative source for user data.

Features:
    - User Enumeration: Query and search users stored in Keycloak
    - User Creation: Create users in Keycloak via Plone's registration workflow
    - User Properties: Fetch user properties (email, fullname) from Keycloak
    - Group Sync: One-way synchronization of groups and memberships from
      Keycloak to native Plone groups

Architecture:
    The plugin implements multiple PAS interfaces:
    - IUserAdderPlugin: Intercepts user creation to create users in Keycloak
    - IUserEnumerationPlugin: Provides user enumeration from Keycloak
    - IPropertiesPlugin: Provides user properties from Keycloak

    Group synchronization is handled separately via:
    - Event subscriber on user login (automatic sync)
    - Browser view for manual/scheduled sync

Modules:
    - plugin: KeycloakPlugin PAS plugin implementation
    - client: KeycloakAdminClient REST API client
    - group_sync: Group and membership synchronization logic
    - interfaces: Zope interface definitions
    - browser: Browser views for admin operations

Example:
    After installation and configuration, users created through Plone's
    registration are automatically created in Keycloak. User searches
    return results from Keycloak when IUserEnumerationPlugin is active.

See Also:
    README.md for installation and configuration instructions.
"""
from AccessControl.Permissions import manage_users
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
from zope.i18nmessageid import MessageFactory
import logging


_ = MessageFactory("wcs.keycloak")
logger = logging.getLogger("wcs.keycloak")


def initialize(context):
    """Initialize the Keycloak plugin."""
    from wcs.keycloak import plugin

    registerMultiPlugin(plugin.KeycloakPlugin.meta_type)

    context.registerClass(
        plugin.KeycloakPlugin,
        permission=manage_users,
        constructors=(
            plugin.manage_addKeycloakPluginForm,
            plugin.manage_addKeycloakPlugin,
        ),
        visibility=None,
    )
