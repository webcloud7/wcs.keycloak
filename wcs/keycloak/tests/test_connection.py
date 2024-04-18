from wcs.keycloak.client import KEYCLOAK_CONNECTION_KEY
from wcs.keycloak.client import KeycloakClient
from wcs.keycloak.client import thread_local_data
from wcs.keycloak.tests import FunctionalTesting
import transaction


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

    def test_admin_succesful(self):
        admin = KeycloakClient(self.plugin).admin()
        self.assertIn('access_token', admin.connection._token)

    def test_admin_connection_unsuccessful(self):
        self.plugin.manage_changeProperties(client_secret='wrong_secret')
        admin = KeycloakClient(self.plugin).admin()
        self.assertIsNone(admin)

        self.plugin.manage_changeProperties(server_url='http://localhost:1234')
        admin = KeycloakClient(self.plugin).admin()
        self.assertIsNone(admin)

        self.plugin.manage_changeProperties(client_id='wrong-client')
        admin = KeycloakClient(self.plugin).admin()
        self.assertIsNone(admin)

        self.plugin.manage_changeProperties(realm_name='wrong-realm')
        admin = KeycloakClient(self.plugin).admin()
        self.assertIsNone(admin)

    def test_make_sure_connection_gets_invalidated_if_plugin_modified(self):
        KeycloakClient(self.plugin).admin()
        connection_id = id(getattr(thread_local_data, KEYCLOAK_CONNECTION_KEY)['connection'])
        KeycloakClient(self.plugin).admin()
        same_connection_id = id(getattr(thread_local_data, KEYCLOAK_CONNECTION_KEY)['connection'])
        self.assertEqual(connection_id, same_connection_id)

        self.plugin.manage_changeProperties(title='new title')
        self.plugin._p_changed = True
        transaction.commit()
        KeycloakClient(self.plugin).admin()
        new_connection_id = id(getattr(thread_local_data, KEYCLOAK_CONNECTION_KEY)['connection'])
        self.assertNotEqual(connection_id, new_connection_id)

    def test_list_groups(self):
        client = KeycloakClient(self.plugin)
        groups = client.get_groups()
        self.assertEqual(2, len(groups))

        self.assertSequenceEqual(
            list(map(lambda group: group['name'], groups)),
            ['Group Two', 'Group Öne']
        )

    def test_list_users(self):
        client = KeycloakClient(self.plugin)
        users = client.get_users()
        self.assertEqual(5, len(users))

        self.assertSequenceEqual(
            list(map(lambda user: user['username'], users)),
            ['hans', 'muster', 'praesent.nonummy', 'user1', 'user2']
        )
