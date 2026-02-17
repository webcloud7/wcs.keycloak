"""Browser views for wcs.keycloak.

This package contains browser views for administrative operations.

Views:
    @@sync-keycloak-groups: Trigger manual group synchronization from Keycloak
        to Plone. Requires Manager role. Returns JSON response with sync
        statistics.

Usage:
    The sync view can be called manually via browser or scheduled via cron::

        # curl example
        curl -u admin:secret https://plone.example.com/@@sync-keycloak-groups

    Response format::

        {
            "success": true,
            "message": "Sync complete: ...",
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
"""
