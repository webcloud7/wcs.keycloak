# wcs.keycloak

Keycloak integration for Plone 6.

## Features

- **PAS Plugin**: Pluggable Authentication Service plugin for Keycloak integration
- **User Enumeration**: Query and list users from Keycloak
- **User Creation**: Create users in Keycloak through Plone's registration workflow
- **User Properties**: Retrieve user properties (email, fullname) from Keycloak
- **Group Synchronization**: One-way sync of groups and memberships from Keycloak to Plone
- **User Synchronization**: One-way sync of users from Keycloak to the plugin's local storage

## Architecture

The plugin implements multiple PAS (Pluggable Authentication Service) interfaces:

- **IUserAdderPlugin**: Intercepts user creation to create users in Keycloak
- **IUserEnumerationPlugin**: Provides user enumeration from Keycloak
- **IPropertiesPlugin**: Provides user properties from Keycloak

Group and user synchronization is handled separately via event subscribers (automatic on login) and browser views (manual/scheduled).

### Modules

| Module | Description |
|--------|-------------|
| `plugin` | `KeycloakPlugin` PAS plugin with `_v_` volatile client caching |
| `client` | `KeycloakAdminClient` REST API client using OAuth2 client credentials flow with automatic token refresh |
| `sync` | Group sync, membership sync, `sync_all()` orchestrator. Groups are prefixed with `keycloak_` to coexist with native Plone groups |
| `user_sync` | User sync to `_user_storage` OOBTree |
| `interfaces` | `IKeycloakLayer` browser layer, `IKeycloakPlugin` marker interface |
| `browser/base` | `BaseSyncView` base class for the 3 sync views |
| `browser/user_management` | Overrides for Plone's user/group control panels with Keycloak sync buttons and admin links |

### Sync Strategy

Keycloak is the single source of truth. All sync operations are one-way from Keycloak to Plone. Changes to synced groups or users in Plone will be overwritten on the next sync.

Groups synced from Keycloak are prefixed with `keycloak_` to distinguish them from native Plone groups. This allows clear identification, safe deletion, and coexistence with native groups.

### Client Authentication

The `KeycloakAdminClient` authenticates using the `client_credentials` OAuth2 grant type. Tokens are automatically refreshed when they expire (on 401 response). The client provides operations for user management (create, search, get, email actions) and group management (create, delete, search, membership).

### Testing Infrastructure

All tests run against a real Keycloak Docker container (no mocks):

| Component | Description |
|-----------|-------------|
| `BaseDockerServiceLayer` | Base layer for running Docker containers as test fixtures |
| `KeyCloakLayer` | Starts Keycloak Docker container and creates test realm |
| `KeycloakTestMixin` | Utilities for admin client creation, authentication, user/group cleanup |
| `KeycloakPluginTestMixin` | Plugin setup with interface activation and service account configuration |

## Installation

Add `wcs.keycloak` to your Plone installation requirements:

```
wcs.keycloak
```

After installation, install the add-on profile through the Plone control panel or via GenericSetup.

## Keycloak Client Setup

Before configuring the plugin, you need to create a service account client in Keycloak with the appropriate permissions.

### Creating the Service Account Client

1. Log into your Keycloak Admin Console
2. Select your realm
3. Navigate to **Clients** and click **Create client**
4. Configure the client:
   - **Client ID**: Choose a descriptive name (e.g., `plone-service-account`)
   - **Client Protocol**: `openid-connect`
5. On the **Capability config** tab, enable:
   - **Client authentication**: On (enables the Credentials tab)
   - **Service accounts roles**: On
6. Click **Save**

### Assigning Required Roles

The service account needs permissions to manage users and groups:

1. Go to your client's **Service accounts roles** tab
2. Click **Assign role**
3. Filter by clients and select **realm-management**
4. Assign these roles:
   - `manage-users` - Required for creating users and sending emails
   - `view-users` - Required for user enumeration
   - `query-users` - Required for user search

### Getting the Client Secret

1. Go to your client's **Credentials** tab
2. Copy the **Client secret** value

## Plugin Configuration

### Adding the Plugin via ZMI

1. Navigate to your Plone site's ZMI: `/acl_users/manage_main`
2. Select "Keycloak Plugin" from the dropdown and click **Add**
3. Enter the plugin ID (e.g., `keycloak`)
4. Configure the connection settings

### Connection Properties

| Property | Description | Example |
|----------|-------------|---------|
| **Server URL** | Base URL of your Keycloak server | `https://keycloak.example.com` |
| **Realm** | The Keycloak realm name | `my-realm` |
| **Admin Client ID** | Service account client ID | `plone-service-account` |
| **Admin Client Secret** | Service account client secret | `your-secret-here` |

### User Creation Options

These options control behavior when users are created through Plone's registration:

| Property | Description | Default |
|----------|-------------|---------|
| **Send password reset email** | Send UPDATE_PASSWORD action email | `True` |
| **Send verify email** | Send VERIFY_EMAIL action email | `True` |
| **Require 2FA/TOTP setup** | Require CONFIGURE_TOTP action | `False` |
| **Email link lifespan** | How long email links are valid (seconds) | `86400` (24h) |
| **Redirect URI** | Where to redirect after Keycloak actions | (empty) |
| **Redirect Client ID** | Client ID for redirect | (empty) |

### Group Sync Options

| Property | Description | Default |
|----------|-------------|---------|
| **Enable Keycloak Group Sync** | Sync groups on user login | `False` |

### User Sync Options

| Property | Description | Default |
|----------|-------------|---------|
| **Enable Keycloak User Sync** | Sync users to local storage | `False` |

### Activating Plugin Interfaces

After adding the plugin, activate the required interfaces in ZMI under `acl_users/plugins/manage_main`:

- **IUserAdderPlugin**: Enable to create users in Keycloak during registration
- **IUserEnumerationPlugin**: Enable to enumerate/search users from Keycloak
- **IPropertiesPlugin**: Enable to fetch user properties from Keycloak

## Group Synchronization

The group sync feature provides one-way synchronization from Keycloak to Plone. Keycloak is the authoritative source for group membership.

### How It Works

1. Groups from Keycloak are created in Plone with a `keycloak_` prefix
2. Group memberships are synced to match Keycloak
3. Groups deleted in Keycloak are removed from Plone
4. Native Plone groups (without the prefix) are not affected

### Automatic Sync on Login

When `Enable Keycloak Group Sync` is enabled:
- All groups are synced when any user logs in
- The logged-in user's group memberships are updated

### Manual/Scheduled Group Sync

Trigger a group-only sync by calling the group sync endpoint:

**curl (cron job)**:
```bash
curl -u admin:secret https://plone.example.com/@@sync-keycloak-groups
```

### Group Sync Response Format

```json
{
    "success": true,
    "message": "Sync complete: 5 groups created, 0 updated, 0 deleted. 12 users added to groups, 0 removed.",
    "stats": {
        "groups_created": 5,
        "groups_updated": 0,
        "groups_deleted": 0,
        "users_added": 12,
        "users_removed": 0,
        "errors": 0
    }
}
```

## User Synchronization

The user sync feature provides one-way synchronization of users from Keycloak to the plugin's local storage. This ensures that user properties (email, fullname) are available locally without querying Keycloak on every request.

### How It Works

1. All users from Keycloak are fetched and stored in the plugin's local storage
2. User properties (email, first name, last name) are kept in sync
3. Users deleted in Keycloak are removed from local storage

### Dedicated User Sync Endpoint

Trigger a standalone user sync by calling the user sync endpoint:

**curl (cron job)**:
```bash
curl -u admin:secret https://plone.example.com/@@sync-keycloak-users
```

### User Sync Response Format

```json
{
    "success": true,
    "message": "User sync complete: 50 users synced, 2 removed.",
    "stats": {
        "users_synced": 50,
        "users_removed": 2,
        "errors": 0
    }
}
```

## Full Synchronization

The `@@sync-keycloak` view performs a complete synchronization of all Keycloak data to Plone. It combines group sync, membership sync, user sync (when enabled), and cleanup of deleted users into a single operation.

This is the recommended endpoint for cron jobs that need to keep everything in sync.

**curl (cron job)**:
```bash
curl -u admin:secret https://plone.example.com/@@sync-keycloak
```

### Full Sync Response Format

When user sync is enabled:

```json
{
    "success": true,
    "message": "Sync complete: 5 groups created, 0 updated, 0 deleted. 12 users added to groups, 0 removed. User sync: 50 synced, 2 removed.",
    "stats": {
        "groups_created": 5,
        "groups_updated": 0,
        "groups_deleted": 0,
        "users_added": 12,
        "users_removed": 0,
        "users_synced": 50,
        "users_sync_removed": 2,
        "users_cleaned": 0,
        "errors": 0
    }
}
```

When user sync is disabled, the response includes cleanup stats instead:

```json
{
    "stats": {
        "groups_created": 5,
        "groups_updated": 0,
        "groups_deleted": 0,
        "users_added": 12,
        "users_removed": 0,
        "users_cleaned": 0,
        "errors": 0
    }
}
```

### Sync Endpoints Overview

| Endpoint | Scope | Use Case |
|----------|-------|----------|
| `@@sync-keycloak` | Groups + memberships + users + cleanup | Recommended for cron jobs |
| `@@sync-keycloak-groups` | Groups + memberships only | When you only need group data |
| `@@sync-keycloak-users` | Users only | When you only need user data |

## Usage Examples

### Querying Users from Keycloak

**Python (requests)**:
```python
import requests

# Search users via Plone's user enumeration
response = requests.get(
    'https://plone.example.com/@users',
    params={'query': 'john'},
    headers={'Accept': 'application/json'},
    auth=('admin', 'secret')
)
users = response.json()
```

**JavaScript (fetch)**:
```javascript
const response = await fetch('https://plone.example.com/@users?query=john', {
    headers: {
        'Accept': 'application/json',
        'Authorization': 'Basic ' + btoa('admin:secret')
    }
});
const users = await response.json();
```

### Creating Users via Registration

Users created through Plone's registration form (or `@users` endpoint) are automatically created in Keycloak when the IUserAdderPlugin is active.

**Python (requests)**:
```python
import requests

response = requests.post(
    'https://plone.example.com/@users',
    json={
        'username': 'newuser',
        'email': 'newuser@example.com',
        'fullname': 'New User'
    },
    headers={'Accept': 'application/json', 'Content-Type': 'application/json'},
    auth=('admin', 'secret')
)
```

The user will:
1. Be created in Keycloak
2. Receive an email with actions based on plugin configuration (password setup, email verification, etc.)

### Working with Synced Groups

Synced groups can be used like any Plone group:

**Python (requests)**:
```python
import requests

# List groups (includes keycloak_ prefixed groups)
response = requests.get(
    'https://plone.example.com/@groups',
    headers={'Accept': 'application/json'},
    auth=('admin', 'secret')
)
groups = response.json()

# Get members of a synced group
response = requests.get(
    'https://plone.example.com/@groups/keycloak_developers',
    headers={'Accept': 'application/json'},
    auth=('admin', 'secret')
)
group = response.json()
print(group['users'])
```

## Testing

The package includes comprehensive integration tests that run against a real Keycloak instance using Docker.

### Running Tests

```bash
make install
make test
```

Or run specific tests:

```bash
bin/test -s wcs.keycloak -t test_enumeration
bin/test -s wcs.keycloak -t TestKeycloakEnumerateUsers
```

### Test Infrastructure

The testing module provides:

- `KeyCloakLayer`: Test layer that starts a Keycloak Docker container
- `KeycloakTestMixin`: Mixin with utilities for Keycloak admin operations
- `KeycloakPluginTestMixin`: Extended mixin for plugin integration tests

## Development

```bash
# Create virtual environment and install dependencies
make install

# Run tests
make test

# Start development instance
make start
```

## License

GPL-2.0
