"""Keycloak integration for Plone 6."""
from AccessControl.Permissions import manage_users
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
from zope.i18nmessageid import MessageFactory


_ = MessageFactory("wcs.keycloak")


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
