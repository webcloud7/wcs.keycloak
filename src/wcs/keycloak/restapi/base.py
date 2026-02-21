"""Base class for Keycloak sync REST API services."""

from plone.protect.interfaces import IDisableCSRFProtection
from plone.restapi.services import Service
from zope.interface import alsoProvides


class BaseSyncService(Service):
    """Base class for Keycloak sync REST API services."""

    disabled_message = "Sync is not enabled"

    def is_enabled(self):
        raise NotImplementedError

    def run_sync(self):
        raise NotImplementedError

    def build_message(self, stats):
        raise NotImplementedError

    def reply(self):
        alsoProvides(self.request, IDisableCSRFProtection)

        if not self.is_enabled():
            self.request.response.setStatus(400)
            return {
                "success": False,
                "message": self.disabled_message,
            }

        try:
            stats = self.run_sync()
            message = self.build_message(stats)

            if stats.get("errors", 0) > 0:
                message += f" {stats['errors']} errors occurred."

            return {
                "success": True,
                "message": message,
                "stats": stats,
            }

        except Exception as e:
            self.request.response.setStatus(500)
            return {
                "success": False,
                "message": f"Sync failed: {e!s}",
            }
