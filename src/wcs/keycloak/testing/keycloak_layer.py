"""Keycloak Docker test layer."""

from wcs.keycloak.testing.docker import BaseDockerServiceLayer
from wcs.keycloak.testing.mixins import KEYCLOAK_SERVER_URL

import os
import requests
import time


class KeyCloakLayer(BaseDockerServiceLayer):
    """Test layer that provides a running Keycloak instance."""

    name = "Keycloak service"
    container_name = "keycloak_test"
    image_name = "quay.io/keycloak/keycloak:22.0.2"
    port = "8000:8080"
    env = {
        "KEYCLOAK_ADMIN": "admin",
        "KEYCLOAK_ADMIN_PASSWORD": "admin",
        "KC_HEALTH_ENABLED": "true",
        "KC_METRICS_ENABLED": "true",
    }
    command = "start-dev"
    admin_session = None

    def setUp(self):
        """Set up the layer, starting Keycloak and creating test realm."""
        super().setUp()
        self.admin_session = requests.Session()
        self.admin_session.headers.update({
            "Content-Type": "application/x-www-form-urlencoded"
        })
        self._create_realm()

    def testSetUp(self):
        """Set up for each test, exposing realm management methods."""
        super().testSetUp()
        self["create_realm"] = self._create_realm
        self["delete_realm"] = self._delete_realm

    def testTearDown(self):
        """Tear down after each test."""
        super().testTearDown()
        del self["create_realm"]
        del self["delete_realm"]

    def tearDown(self):
        """Tear down the layer, deleting test realm."""
        self._delete_realm()
        super().tearDown()

    def _configure(self):
        """Configure admin session with authentication token."""
        # Import realm
        access_token = requests.post(
            f"{KEYCLOAK_SERVER_URL}/realms/master/protocol/openid-connect/token",
            data={
                "username": "admin",
                "password": "admin",
                "grant_type": "password",
                "client_id": "admin-cli",
            },
        ).json()["access_token"]

        self.admin_session.headers.update({"Authorization": f"Bearer {access_token}"})

    def _create_realm(self, filename="saml-test-realm.json"):
        """Create the test realm in Keycloak.

        Args:
            filename: Name of the realm JSON file to import.
        """
        self._configure()
        self.admin_session.headers.update({"Content-Type": "application/json"})

        response = self.admin_session.get(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/saml-test"
        )
        if response.status_code == 200:
            self._delete_realm()

        filepath = os.path.join(
            os.path.dirname(__file__), "..", "tests", "assets", filename
        )
        with open(filepath, "rb") as f:
            realm_data = f.read()
            port = os.environ.get("WSGI_SERVER_PORT", "65035")
            realm_data_str = realm_data.decode("utf-8")
            realm_data_str = realm_data_str.replace(
                "http://localhost:8080/plone", f"http://localhost:{port}/plone"
            )
            realm_data = realm_data_str.encode("utf-8")

        response = self.admin_session.post(
            f"{KEYCLOAK_SERVER_URL}/admin/realms", data=realm_data
        )
        assert response.status_code == 201, "Realm not created"

    def _delete_realm(self):
        """Delete the test realm from Keycloak."""
        self._configure()
        self.admin_session.headers.update({"Content-Type": "application/json"})
        response = self.admin_session.delete(
            f"{KEYCLOAK_SERVER_URL}/admin/realms/saml-test"
        )
        assert response.status_code == 204, "Realm not deleted"

    def _wait_for_service(self):
        """Wait for Keycloak to become ready."""
        counter = 0
        while not self._test_connect_service():
            if counter == self.MAX_CONNECTION_RETRIES:
                raise Exception("Cannot connect to keycloak service")
            time.sleep(1)
            counter += 1

    def _test_connect_service(self):
        """Test if Keycloak is running and healthy.

        Returns:
            True if Keycloak is ready, False otherwise.
        """
        try:
            response = requests.get(f"{KEYCLOAK_SERVER_URL}/health/ready")
            return response.status_code == 200 and response.json()["status"] == "UP"
        except requests.exceptions.ConnectionError:
            return False


KEYCLOAK_FIXTURE = KeyCloakLayer()
