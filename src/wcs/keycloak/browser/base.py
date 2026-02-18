"""Base class for Keycloak sync browser views."""

from plone.protect.interfaces import IDisableCSRFProtection
from Products.Five.browser import BrowserView
from zope.interface import alsoProvides

import json


class BaseSyncView(BrowserView):
    """Base class for Keycloak sync views."""

    disabled_message = "Sync is not enabled"

    def is_enabled(self):
        raise NotImplementedError

    def run_sync(self):
        raise NotImplementedError

    def build_message(self, stats):
        raise NotImplementedError

    def __call__(self):
        alsoProvides(self.request, IDisableCSRFProtection)
        self.request.response.setHeader("Content-Type", "application/json")

        if not self.is_enabled():
            self.request.response.setStatus(400)
            return json.dumps({
                "success": False,
                "message": self.disabled_message,
            })

        try:
            stats = self.run_sync()
            message = self.build_message(stats)

            if stats.get("errors", 0) > 0:
                message += f" {stats['errors']} errors occurred."

            return json.dumps({
                "success": True,
                "message": message,
                "stats": stats,
            })

        except Exception as e:
            self.request.response.setStatus(500)
            return json.dumps({
                "success": False,
                "message": f"Sync failed: {e!s}",
            })
