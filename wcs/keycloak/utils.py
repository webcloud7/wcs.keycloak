from plone import api
import logging


LOGGER = logging.getLogger(__name__)
PLUGIN_ID = 'keycloak'


def install_plugin():
    """Setup keycloak plugin"""

    from wcs.keycloak.plugin import KeycloakPasPlugin
    pas = api.portal.get_tool('acl_users')

    # Create plugin if it does not exist.
    if PLUGIN_ID not in pas.objectIds():
        plugin = KeycloakPasPlugin(
            id_=PLUGIN_ID,
            title="Keycloak users/groups",
        )
        pas._setObject(PLUGIN_ID, plugin)
        LOGGER.info("Created %s in acl_users.", PLUGIN_ID)
    plugin = getattr(pas, PLUGIN_ID)

    # Activate all supported interfaces for this plugin.
    activate = []
    plugins = pas.plugins
    for info in plugins.listPluginTypeInfo():
        interface = info["interface"]
        interface_name = info["id"]
        if plugin.testImplements(interface):
            activate.append(interface_name)
            LOGGER.info(
                "Activating interface %s for plugin %s", interface_name, PLUGIN_ID
            )

    plugin.manage_activateInterfaces(activate)
    LOGGER.info("Plugins activated.")

    return plugin
