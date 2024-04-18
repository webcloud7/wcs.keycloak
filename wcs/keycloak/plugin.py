from AccessControl.class_init import InitializeClass
from AccessControl.SecurityInfo import ClassSecurityInfo
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PlonePAS.interfaces.group import IGroupIntrospection
from Products.PluggableAuthService.interfaces.plugins import IGroupEnumerationPlugin
from Products.PluggableAuthService.interfaces.plugins import IGroupsPlugin
from Products.PluggableAuthService.interfaces.plugins import IUserEnumerationPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from wcs.keycloak.client import KeycloakClient
from zope.interface import Interface
import logging

logger = logging.getLogger(__name__)


manage_addKeycloakPasPluginForm = PageTemplateFile("templates/add_plugin", globals())


def manage_addKeycloakPasPlugin(self, id_, title='', RESPONSE=None):
    """Add a keycloak users/groups plugin.
    """
    plugin = KeycloakPasPlugin(id_, title)
    self._setObject(plugin.getId(), plugin)

    if RESPONSE is not None:
        RESPONSE.redirect("manage_workspace")


class IKeycloakPasPlugin(Interface):
    """Marker interfaces for keycloak plugins"""


class KeycloakPasPlugin(BasePlugin):
    """Keycloak users/groups plugin.
    """

    meta_type = "Keycloak users/groups plugin"
    security = ClassSecurityInfo()

    server_url = ""
    client_id = ""
    client_secret = ""
    realm_name = ""

    _properties = (
        dict(id='server_url', label='Server URL', type='string', mode='w'),
        dict(id='client_id', label='Client ID', type='string', mode='w'),
        dict(id='client_secret', label='Client Secret', type='string', mode='w'),
        dict(id='realm_name', label='Realm Name', type='string', mode='w'),
    )

    def __init__(self, id_, title=None):
        self._setId(id_)
        self.title = title

    def enumerateGroups(self, id=None, exact_match=False, sort_by=None, max_results=None, **kw):
        """Enumerate groups
        """
        admin = KeycloakClient(self).admin()
        
        return []

    def getGroupsForPrincipal(self, principal, request=None):
        """Get groups for principal
        """
        return []

    def challenge(self, request, response):
        """Go to the login view of the PAS plugin
        """
        logger.info(f'Challenge. Came from {request.URL}')
        url = f"{self.absolute_url()}/require_login?came_from={request.URL}"
        response.redirect(url, lock=1)
        return True


InitializeClass(KeycloakPasPlugin)

classImplements(
    KeycloakPasPlugin,
    IKeycloakPasPlugin,
    IGroupIntrospection,
    IGroupsPlugin,
    IGroupEnumerationPlugin,
    IUserEnumerationPlugin,
)
