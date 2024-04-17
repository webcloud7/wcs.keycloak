from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection
from threading import local


KEYCLOAK_CONNECTION_KEY = 'wcs.keycloak.connection'


class KeycloakClient:
    def __init__(self, plugin):

        self.server_url = plugin.getProperty('server_url', None)
        self.realm_name = plugin.getProperty('realm_name', None)
        self.client_id = plugin.getProperty('client_id', None)
        self.client_secret = plugin.getProperty('client_secret', None)
        self._local = local()

    def enabled(self):
        return all(
            [
                self.server_url,
                self.realm_name,
                self.client_id,
                self.client_secret
            ]
        )

    def admin(self):
        if not self.enabled:
            return 

        connection = None
        if not hasattr(self._local, KEYCLOAK_CONNECTION_KEY):
            connection = KeycloakOpenIDConnection(
                server_url=self.server_url,
                client_id=self.client_id,
                realm_name=self.realm_name,
                client_secret_key=self.client_secret
            )
            setattr(self._local, KEYCLOAK_CONNECTION_KEY, connection)
        else:
            connection = getattr(self._local, KEYCLOAK_CONNECTION_KEY)

        return KeycloakAdmin(connection=connection)

    def get_users(self, query):
        return []

    def get_groups(self, query):
        return self.admin.get_groups(query=query)
