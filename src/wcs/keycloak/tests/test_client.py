"""Tests for KeycloakAdminClient API methods.

This module contains tests for the core Keycloak client functionality:
- Authentication
- User CRUD operations
- Group CRUD operations
- User-group membership operations
- URL construction
- Error handling
"""
from plone import api
from wcs.keycloak.client import KeycloakAdminClient
from wcs.keycloak.client import KeycloakAuthenticationError
from wcs.keycloak.client import KeycloakUserCreationError
from wcs.keycloak.client import KeycloakUserExistsError
from wcs.keycloak.testing.mixins import KEYCLOAK_ADMIN_PASSWORD
from wcs.keycloak.testing.mixins import KEYCLOAK_ADMIN_USER
from wcs.keycloak.testing.mixins import KEYCLOAK_REALM
from wcs.keycloak.testing.mixins import KEYCLOAK_SERVER_URL
from wcs.keycloak.testing.mixins import KeycloakTestMixin
from wcs.keycloak.tests import FunctionalTesting
import requests
import transaction


class TestKeycloakAdminClient(KeycloakTestMixin, FunctionalTesting):
    """Tests for KeycloakAdminClient API methods."""

    def setUp(self):
        super().setUp()
        self._setup_keycloak_client()

    def tearDown(self):
        self._teardown_keycloak_client()
        super().tearDown()

    def test_authentication(self):
        token = self.client._authenticate()
        self.assertIsNotNone(token)
        self.assertTrue(len(token) > 0)

    def test_create_user(self):
        username = 'test_create_user_123'
        email = 'test_create_user_123@example.com'

        self._cleanup_user(username)
        self._created_users.append(username)

        user_id = self.client.create_user(
            username=username,
            email=email,
            first_name='Test',
            last_name='User',
            enabled=True,
        )

        self.assertIsNotNone(user_id)
        self.assertTrue(len(user_id) > 0)

        found_id = self.client.get_user_id_by_username(username)
        self.assertEqual(user_id, found_id)

    def test_create_user_already_exists(self):
        username = 'test_duplicate_user_123'
        email = 'test_duplicate_user_123@example.com'

        self._created_users.append(username)

        # Create user first time
        self.client.create_user(
            username=username,
            email=email,
            first_name='Test',
            last_name='Duplicate',
        )

        # Try to create same user again
        with self.assertRaises(KeycloakUserExistsError):
            self.client.create_user(
                username=username,
                email='different@example.com',  # Different email, same username
                first_name='Test',
                last_name='Duplicate',
            )

    def test_get_user_id_by_username(self):
        username = 'test_get_user_123'
        email = 'test_get_user_123@example.com'

        self._created_users.append(username)

        created_id = self.client.create_user(
            username=username,
            email=email,
            first_name='Test',
            last_name='GetUser',
        )

        found_id = self.client.get_user_id_by_username(username)
        self.assertEqual(created_id, found_id)

    def test_get_user_by_username(self):
        username = 'test_get_user_123'
        email = 'test_get_user_123@example.com'

        self._created_users.append(username)

        created_id = self.client.create_user(
            username=username,
            email=email,
            first_name='Test',
            last_name='GetUser',
        )

        user = self.client.get_user(username)
        self.assertEqual(created_id, user['id'])
        self.assertEqual(username, user['username'])
        self.assertEqual(email, user['email'])

    def test_get_user_id_by_username_not_found(self):
        user_id = self.client.get_user_id_by_username('nonexistent_user_xyz_123')
        self.assertIsNone(user_id)

    def test_get_user_id_by_email(self):
        username = 'test_get_by_email_123'
        email = 'test_get_by_email_123@example.com'

        self._created_users.append(username)

        created_id = self.client.create_user(
            username=username,
            email=email,
            first_name='Test',
            last_name='GetByEmail',
        )

        found_id = self.client.get_user_id_by_email(email)
        self.assertEqual(created_id, found_id)

    def test_set_user_required_actions(self):
        username = 'test_required_actions_123'
        email = 'test_required_actions_123@example.com'

        self._created_users.append(username)

        user_id = self.client.create_user(
            username=username,
            email=email,
            first_name='Test',
            last_name='RequiredActions',
        )

        result = self.client.set_user_required_actions(
            user_id=user_id,
            actions=['UPDATE_PASSWORD', 'CONFIGURE_TOTP'],
        )

        self.assertTrue(result)


class TestKeycloakSearchUsers(KeycloakTestMixin, FunctionalTesting):
    """Tests for the search_users method of KeycloakAdminClient."""

    def setUp(self):
        super().setUp()
        self._setup_keycloak_client()

    def tearDown(self):
        self._teardown_keycloak_client()
        super().tearDown()

    def test_search_users_by_username(self):
        username = 'test_search_user_123'
        email = 'test_search_user_123@example.com'

        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email=email,
            first_name='Search',
            last_name='User',
        )

        users = self.client.search_users(username=username)

        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]['username'], username)

    def test_search_users_by_email(self):
        username = 'test_search_email_123'
        email = 'test_search_email_123@example.com'

        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email=email,
            first_name='Search',
            last_name='Email',
        )

        users = self.client.search_users(email=email)

        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]['email'], email)

    def test_search_users_by_general_search(self):
        username = 'test_search_general_123'
        email = 'test_search_general_123@example.com'

        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email=email,
            first_name='UniqueFirstName',
            last_name='UniqueLastName',
        )

        users = self.client.search_users(search='UniqueFirstName')

        self.assertTrue(len(users) >= 1)
        usernames = [u['username'] for u in users]
        self.assertIn(username, usernames)

    def test_search_users_exact_match(self):
        username = 'test_exact_match_123'
        email = 'test_exact_match_123@example.com'

        self._cleanup_user(username)
        self._created_users.append(username)

        self.client.create_user(
            username=username,
            email=email,
            first_name='Exact',
            last_name='Match',
        )

        users = self.client.search_users(username=username, exact=True)

        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]['username'], username)

    def test_search_users_max_results(self):
        users = self.client.search_users(search='', max_results=2)

        self.assertTrue(len(users) <= 2)

    def test_search_users_not_found(self):
        users = self.client.search_users(username='nonexistent_user_xyz_999')

        self.assertEqual(len(users), 0)


class TestKeycloakSearchGroups(KeycloakTestMixin, FunctionalTesting):
    """Integration tests for group search methods in KeycloakAdminClient."""

    def setUp(self):
        super().setUp()
        self._setup_keycloak_client()

    def tearDown(self):
        self._teardown_keycloak_client()
        super().tearDown()

    def test_create_group(self):
        group_name = 'test_create_group_123'

        group_id = self.client.create_group(group_name)
        self._created_groups.append(group_id)

        self.assertIsNotNone(group_id)
        self.assertTrue(len(group_id) > 0)

        # Verify group exists
        group = self.client.get_group(group_id)
        self.assertIsNotNone(group)
        self.assertEqual(group['name'], group_name)

    def test_delete_group(self):
        group_name = 'test_delete_group_123'
        group_id = self.client.create_group(group_name)

        result = self.client.delete_group(group_id)

        self.assertTrue(result)
        # Verify group is deleted
        group = self.client.get_group(group_id)
        self.assertIsNone(group)

    def test_search_groups_returns_list(self):
        group_name = 'test_search_groups_123'
        group_id = self.client.create_group(group_name)
        self._created_groups.append(group_id)

        groups = self.client.search_groups()

        self.assertIsInstance(groups, list)
        group_names = [g['name'] for g in groups]
        self.assertIn(group_name, group_names)

    def test_search_groups_with_search_term(self):
        group_name = 'test_search_term_unique_xyz'
        group_id = self.client.create_group(group_name)
        self._created_groups.append(group_id)

        groups = self.client.search_groups(search='unique_xyz')

        self.assertIsInstance(groups, list)
        self.assertTrue(len(groups) >= 1)
        group_names = [g['name'] for g in groups]
        self.assertIn(group_name, group_names)

    def test_search_groups_with_max_results(self):
        # Create multiple groups
        for i in range(3):
            group_id = self.client.create_group(f'test_max_results_{i}')
            self._created_groups.append(group_id)

        groups = self.client.search_groups(max_results=2)

        self.assertTrue(len(groups) <= 2)

    def test_search_groups_with_exact_match(self):
        group_name = 'test_exact_match_group_123'
        group_id = self.client.create_group(group_name)
        self._created_groups.append(group_id)

        groups = self.client.search_groups(search=group_name, exact=True)

        self.assertIsInstance(groups, list)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]['name'], group_name)

    def test_get_group_returns_group_by_uuid(self):
        group_name = 'test_get_by_uuid_123'
        group_id = self.client.create_group(group_name)
        self._created_groups.append(group_id)

        group = self.client.get_group(group_id)

        self.assertIsNotNone(group)
        self.assertEqual(group['id'], group_id)
        self.assertEqual(group['name'], group_name)

    def test_get_group_returns_none_for_nonexistent_uuid(self):
        group = self.client.get_group('00000000-0000-0000-0000-000000000000')

        self.assertIsNone(group)

    def test_get_group_by_name_returns_group(self):
        group_name = 'test_get_by_name_123'
        group_id = self.client.create_group(group_name)
        self._created_groups.append(group_id)

        group = self.client.get_group_by_name(group_name, exact=True)

        self.assertIsNotNone(group)
        self.assertEqual(group['name'], group_name)
        self.assertEqual(group['id'], group_id)

    def test_get_group_by_name_returns_none_for_nonexistent_name(self):
        group = self.client.get_group_by_name('nonexistent_group_xyz_999', exact=True)

        self.assertIsNone(group)

    def test_add_user_to_group(self):
        # Create user
        username = 'test_add_to_group_user'
        email = 'test_add_to_group_user@example.com'
        self._cleanup_user(username)
        self._created_users.append(username)
        user_id = self.client.create_user(
            username=username, email=email,
            first_name='Test', last_name='AddToGroup',
        )

        # Create group
        group_name = 'test_add_user_group'
        group_id = self.client.create_group(group_name)
        self._created_groups.append(group_id)

        # Add user to group
        result = self.client.add_user_to_group(user_id, group_id)

        self.assertTrue(result)

        # Verify user is in group
        groups = self.client.get_groups_for_user(user_id)
        group_ids = [g['id'] for g in groups]
        self.assertIn(group_id, group_ids)

    def test_remove_user_from_group(self):
        # Create user
        username = 'test_remove_from_group_user'
        email = 'test_remove_from_group_user@example.com'
        self._cleanup_user(username)
        self._created_users.append(username)
        user_id = self.client.create_user(
            username=username, email=email,
            first_name='Test', last_name='RemoveFromGroup',
        )

        # Create group and add user
        group_name = 'test_remove_user_group'
        group_id = self.client.create_group(group_name)
        self._created_groups.append(group_id)
        self.client.add_user_to_group(user_id, group_id)

        # Remove user from group
        result = self.client.remove_user_from_group(user_id, group_id)

        self.assertTrue(result)

        # Verify user is not in group
        groups = self.client.get_groups_for_user(user_id)
        group_ids = [g['id'] for g in groups]
        self.assertNotIn(group_id, group_ids)

    def test_get_groups_for_user_returns_assigned_groups(self):
        # Create user
        username = 'test_user_with_groups_123'
        email = 'test_user_with_groups_123@example.com'
        self._cleanup_user(username)
        self._created_users.append(username)
        user_id = self.client.create_user(
            username=username, email=email,
            first_name='Test', last_name='WithGroups',
        )

        # Create groups and add user
        group1_id = self.client.create_group('test_user_group_1')
        group2_id = self.client.create_group('test_user_group_2')
        self._created_groups.extend([group1_id, group2_id])

        self.client.add_user_to_group(user_id, group1_id)
        self.client.add_user_to_group(user_id, group2_id)

        # Get user's groups
        groups = self.client.get_groups_for_user(user_id)

        self.assertIsInstance(groups, list)
        self.assertEqual(len(groups), 2)
        group_names = [g['name'] for g in groups]
        self.assertIn('test_user_group_1', group_names)
        self.assertIn('test_user_group_2', group_names)


class TestKeycloakClientUrls(FunctionalTesting):
    """Tests for Keycloak client URL construction."""

    def test_token_url(self):
        client = KeycloakAdminClient(
            server_url='https://keycloak.example.com',
            realm='my-realm',
            client_id='test',
            client_secret='secret',
        )

        url = client._get_token_url()

        self.assertEqual(
            url,
            'https://keycloak.example.com/realms/my-realm/protocol/openid-connect/token'
        )

    def test_admin_url(self):
        client = KeycloakAdminClient(
            server_url='https://keycloak.example.com',
            realm='my-realm',
            client_id='test',
            client_secret='secret',
        )

        url = client._get_admin_url()

        self.assertEqual(url, 'https://keycloak.example.com/admin/realms/my-realm')

    def test_trailing_slash_stripped(self):
        client = KeycloakAdminClient(
            server_url='https://keycloak.example.com/',
            realm='my-realm',
            client_id='test',
            client_secret='secret',
        )

        self.assertEqual(client.server_url, 'https://keycloak.example.com')


class TestKeycloakErrors(FunctionalTesting):
    """Tests for Keycloak error handling."""

    def test_authentication_error_wrong_credentials(self):
        client = KeycloakAdminClient(
            server_url=KEYCLOAK_SERVER_URL,
            realm=KEYCLOAK_REALM,
            client_id='invalid-client',
            client_secret='wrong-secret',
        )

        with self.assertRaises(KeycloakAuthenticationError) as ctx:
            client._authenticate()

        self.assertIn('Authentication failed', str(ctx.exception))

    def test_authentication_error_wrong_server_url(self):
        client = KeycloakAdminClient(
            server_url='http://localhost:9999',
            realm=KEYCLOAK_REALM,
            client_id='admin-cli',
            client_secret='',
        )

        with self.assertRaises(KeycloakAuthenticationError) as ctx:
            client._authenticate()

        self.assertIn('Authentication failed', str(ctx.exception))

    def test_user_creation_error_invalid_token(self):
        client = KeycloakAdminClient(
            server_url=KEYCLOAK_SERVER_URL,
            realm=KEYCLOAK_REALM,
            client_id='admin-cli',
            client_secret='',
        )
        # Set an invalid token - will trigger 401 and re-auth attempt
        client._access_token = 'invalid-token'

        with self.assertRaises(KeycloakAuthenticationError):
            client.create_user(
                username='test_unauthorized_user',
                email='test_unauthorized@example.com',
                first_name='Test',
                last_name='Unauthorized',
            )

    def test_user_creation_error_invalid_email(self):
        client = KeycloakAdminClient(
            server_url=KEYCLOAK_SERVER_URL,
            realm=KEYCLOAK_REALM,
            client_id='admin-cli',
            client_secret='',
        )
        # Use password grant for admin authentication
        token_url = f'{KEYCLOAK_SERVER_URL}/realms/master/protocol/openid-connect/token'
        data = {
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': KEYCLOAK_ADMIN_USER,
            'password': KEYCLOAK_ADMIN_PASSWORD,
        }
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        client._access_token = response.json()['access_token']

        with self.assertRaises(KeycloakUserCreationError):
            client.create_user(
                username='test_invalid_email_user',
                email='not-a-valid-email',
                first_name='Test',
                last_name='Invalid',
            )


class TestPluginGetClient(FunctionalTesting):
    """Tests for the KeycloakPlugin.get_client() method."""

    def setUp(self):
        super().setUp()
        self.grant('Manager')

    def _setup_keycloak_plugin(
        self,
        server_url='',
        realm='',
        admin_client_id='',
        admin_client_secret=''
    ):
        from wcs.keycloak.plugin import manage_addKeycloakPlugin
        acl_users = api.portal.get_tool('acl_users')
        if 'keycloak' not in acl_users:
            manage_addKeycloakPlugin(acl_users, 'keycloak', title='Keycloak')
        plugin = acl_users['keycloak']
        plugin.server_url = server_url
        plugin.realm = realm
        plugin.admin_client_id = admin_client_id
        plugin.admin_client_secret = admin_client_secret
        transaction.commit()
        return plugin

    def _remove_keycloak_plugin(self):
        acl_users = api.portal.get_tool('acl_users')
        if 'keycloak' in acl_users:
            acl_users.manage_delObjects(['keycloak'])
            transaction.commit()

    def test_get_client_returns_none_when_not_configured(self):
        plugin = self._setup_keycloak_plugin(
            server_url='',
            realm='',
            admin_client_id='',
            admin_client_secret=''
        )

        self.assertIsNone(
            plugin.get_client(),
            'get_client() should return None when not configured',
        )

    def test_get_client_returns_client_when_configured(self):
        plugin = self._setup_keycloak_plugin(
            server_url='https://keycloak.example.com',
            realm='test-realm',
            admin_client_id='admin-cli',
            admin_client_secret='secret123'
        )

        client = plugin.get_client()

        self.assertIsNotNone(client, 'get_client() should return a client when configured')
        self.assertIsInstance(client, KeycloakAdminClient)
        self.assertEqual(client.server_url, 'https://keycloak.example.com')
        self.assertEqual(client.realm, 'test-realm')

    def test_get_client_returns_cached_instance(self):
        plugin = self._setup_keycloak_plugin(
            server_url='https://keycloak.example.com',
            realm='test-realm',
            admin_client_id='admin-cli',
            admin_client_secret='secret123'
        )

        client1 = plugin.get_client()
        client2 = plugin.get_client()

        self.assertIs(
            client1, client2,
            'get_client() should return the same cached instance',
        )

    def test_get_client_invalidates_cache_on_config_change(self):
        plugin = self._setup_keycloak_plugin(
            server_url='https://keycloak.example.com',
            realm='test-realm',
            admin_client_id='admin-cli',
            admin_client_secret='secret123'
        )

        client1 = plugin.get_client()
        plugin.server_url = 'https://other.example.com'
        client2 = plugin.get_client()

        self.assertIsNot(
            client1, client2,
            'get_client() should return a new instance after config change',
        )
        self.assertEqual(client2.server_url, 'https://other.example.com')
