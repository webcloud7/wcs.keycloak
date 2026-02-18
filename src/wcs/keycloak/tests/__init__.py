"""Test infrastructure for wcs.keycloak."""
from plone.app.testing import FunctionalTesting as PloneFunctionalTesting
from plone.app.testing import PLONE_FIXTURE
from plone.app.testing import PloneSandboxLayer
from plone.app.testing import setRoles
from plone.app.testing import SITE_OWNER_NAME
from plone.app.testing import SITE_OWNER_PASSWORD
from plone.app.testing import TEST_USER_ID
from plone.testing.zope import installProduct
from plone.testing.zope import WSGI_SERVER_FIXTURE
from unittest import TestCase
from wcs.keycloak.testing.keycloak_layer import KEYCLOAK_FIXTURE
from zope.configuration import xmlconfig
import transaction


class KeycloakLayer(PloneSandboxLayer):
    """Plone test layer for wcs.keycloak."""

    defaultBases = (PLONE_FIXTURE,)

    def setUpZope(self, app, configurationContext):
        """Set up Zope with wcs.keycloak."""
        super().setUpZope(app, configurationContext)

        xmlconfig.string(
            '<configure xmlns="http://namespaces.zope.org/zope">'
            '  <include package="plone.autoinclude" file="meta.zcml" />'
            '  <autoIncludePlugins target="plone" />'
            '  <autoIncludePluginsOverrides target="plone" />'
            '</configure>',
            context=configurationContext,
        )

        installProduct(app, 'wcs.keycloak')

    def setUpPloneSite(self, portal):
        """Set up Plone site."""
        super().setUpPloneSite(portal)
        setRoles(portal, TEST_USER_ID, ["Manager"])
        transaction.commit()
        setRoles(portal, TEST_USER_ID, [])


KEYCLOAK_PLONE_FIXTURE = KeycloakLayer()
KEYCLOAK_FUNCTIONAL_TESTING = PloneFunctionalTesting(
    bases=(
        KEYCLOAK_FIXTURE,
        KEYCLOAK_PLONE_FIXTURE,
        WSGI_SERVER_FIXTURE,
    ),
    name='wcs.keycloak:Functional',
)


class FunctionalTesting(TestCase):
    """Base class for wcs.keycloak functional tests.

    Provides common setup and helper properties for API testing.

    Attributes:
        layer: The test layer to use.
        portal: The Plone portal object.
        request: The current request object.
    """

    layer = KEYCLOAK_FUNCTIONAL_TESTING

    @property
    def api_headers(self):
        """Get headers for JSON API requests.

        Returns:
            Dict with Accept header set to application/json.
        """
        return {'Accept': 'application/json'}

    @property
    def api_post_headers(self):
        """Get headers for JSON API POST requests.

        Returns:
            Dict with Accept and Content-Type headers set to application/json.
        """
        return {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

    @property
    def portal_url(self):
        """Get the portal URL for requests.

        Returns:
            The absolute URL of the portal.
        """
        return self.portal.absolute_url()

    @property
    def credentials(self):
        """Get site owner credentials for requests authentication.

        Returns:
            Tuple of (username, password) for HTTP Basic auth with Manager access.
        """
        return (SITE_OWNER_NAME, SITE_OWNER_PASSWORD)

    def setUp(self):
        """Set up test fixtures."""
        self.portal = self.layer['portal']
        self.request = self.layer['request']

    def grant(self, *roles):
        """Grant roles to the test user.

        Args:
            *roles: Role names to grant.
        """
        setRoles(self.portal, TEST_USER_ID, list(roles))
        transaction.commit()
