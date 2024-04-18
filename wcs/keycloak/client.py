from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection
from keycloak.exceptions import KeycloakAuthenticationError
from keycloak.exceptions import KeycloakConnectionError
from threading import local
import logging


LOGGER = logging.getLogger(__name__)
KEYCLOAK_CONNECTION_KEY = 'wcs.keycloak.connection'

thread_local_data = local()


class KeycloakClient:
    def __init__(self, plugin):

        self.plugin = plugin
        self.server_url = plugin.getProperty('server_url', None)
        self.realm_name = plugin.getProperty('realm_name', None)
        self.client_id = plugin.getProperty('client_id', None)
        self.client_secret = plugin.getProperty('client_secret', None)

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
        if not hasattr(thread_local_data, KEYCLOAK_CONNECTION_KEY) or self._modified():
            try:
                connection = KeycloakOpenIDConnection(
                    server_url=self.server_url,
                    client_id=self.client_id,
                    realm_name=self.realm_name,
                    client_secret_key=self.client_secret
                )
                setattr(
                    thread_local_data,
                    KEYCLOAK_CONNECTION_KEY,
                    {'connection': connection, 'modified': self.plugin._p_mtime}
                )
            except (KeycloakAuthenticationError, KeycloakConnectionError) as error:
                LOGGER.error(error)
                if hasattr(thread_local_data, KEYCLOAK_CONNECTION_KEY):
                    delattr(thread_local_data, KEYCLOAK_CONNECTION_KEY)
                return None
        else:
            connection = getattr(thread_local_data, KEYCLOAK_CONNECTION_KEY)['connection']

        return KeycloakAdmin(connection=connection)

    def get_users(self, query=None):
        return self.admin().get_users(query=query)

    def get_groups(self, query=None):
        return self.admin().get_groups(query=query)

    def _modified(self):
        info = getattr(thread_local_data, KEYCLOAK_CONNECTION_KEY, {})
        return info.get('modified') != self.plugin._p_mtime
