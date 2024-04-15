from AccessControl.Permissions import manage_users
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin
from wcs.keycloak import plugin
from zope.i18nmessageid import MessageFactory


_ = MessageFactory("wcs.keycloak")
registerMultiPlugin(plugin.KeycloakPasPlugin.meta_type)


def initialize(context):
    """Initializer called when used as a Zope 2 product."""

    context.registerClass(
        plugin.KeycloakPasPlugin,
        permission=manage_users,
        constructors=(
            plugin.manage_addKeycloakPasPluginForm,
            plugin.manage_addKeycloakPasPlugin,
        ),
        visibility=None)
