from wcs.keycloak.client import KeycloakClient
from wcs.keycloak.tests import FunctionalTesting


class TestKeycloakConnection(FunctionalTesting):

    def setUp(self):
        super().setUp()
        self.grant('Manager')

    def test_enabled(self):
        self.assertTrue(KeycloakClient(self.plugin).enabled())

    def test_disabled(self):
        self.plugin.manage_changeProperties(
            server_url='',
            client_id='',
            client_secret='',
            realm_name=''
        )
        self.assertFalse(KeycloakClient(self.plugin).enabled())
