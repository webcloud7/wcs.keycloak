"""Base Docker service layer for testing."""

from plone.testing import Layer

import logging
import shutil
import subprocess
import sys


LOGGER = logging.getLogger("wcs.keycloak.testing")
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("\n%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
LOGGER.addHandler(handler)


class BaseDockerServiceLayer(Layer):
    """Base layer for Docker-based test services."""

    MAX_CONNECTION_RETRIES = 20

    image_name = None
    container_name = None
    port = None
    name = None
    env = None
    command = None
    retry = 1

    def __init__(self, bases=None, name=None, module=None):
        """Initialize the layer.

        Args:
            bases: Base layers.
            name: Layer name (uses self.name if not provided).
            module: Module for the layer.
        """
        super().__init__(bases, self.name, module)
        self.external_service = None
        self.retry = 3

    def setUp(self):
        """Set up the layer, starting Docker container if needed."""
        super().setUp()

        try:
            if self._test_connect_service():
                # Service is already running
                self.external_service = True
                return
        except Exception:
            self.external_service = False

        if not shutil.which("docker"):
            # No Docker available - service may be starting externally (e.g. CI)
            self._wait_for_service()
            self.external_service = True
            return

        if not self.is_docker_container_available():
            self._create_docker_container()
        self.start_service()

    def tearDown(self):
        """Tear down the layer, stopping Docker container if we started it."""
        if not self.external_service:
            self.stop_service()

    def _run_docker_command(self, command):
        """Run a Docker command.

        Args:
            command: List of command arguments.

        Returns:
            CompletedProcess result.

        Raises:
            RuntimeError: If command fails with error.
        """
        result = subprocess.run(command, capture_output=True, text=True)  # noqa: S603

        if result.stderr:
            raise RuntimeError(f"Command ended with an error: {result.stderr}")
        return result

    def start_service(self):
        """Start the Docker container."""
        result = self._run_docker_command(["docker", "start", self.container_name])
        if result.returncode == 0:
            LOGGER.info(f"{self.name} started: {result.stdout}")

        self._wait_for_service()

    def stop_service(self):
        """Stop the Docker container."""
        result = self._run_docker_command(["docker", "stop", self.container_name])
        if result.returncode == 0:
            LOGGER.info(f"{self.name} stopped: {result.stdout}")

    def _create_docker_container(self, *arguments):
        """Create the Docker container.

        Args:
            *arguments: Optional command arguments (uses defaults if not provided).
        """
        if not arguments:
            arguments = [
                "docker",
                "container",
                "create",
                "--name",
                self.container_name,
                "-p",
                self.port,
            ]
        if self.env:
            for key, value in self.env.items():
                arguments.extend(["-e", f"{key}={value}"])
        arguments.append(self.image_name)

        if self.command:
            arguments.append(self.command)
        result = self._run_docker_command(arguments)
        LOGGER.info(
            f"Created {self.name} container: {self.container_name} ({result.stdout})"
        )

    def is_docker_container_available(self):
        """Check if the Docker container already exists.

        Returns:
            True if container exists, False otherwise.
        """
        result = self._run_docker_command(
            ["docker", "ps", "-q", "-a", "-f", f"name={self.container_name}"],
        )
        if result.stderr:
            raise RuntimeError(
                f"Cannot determine if test image is available: {result.stderr}"
            )
        LOGGER.info(f"{self.name} container available at: {result.stdout}")
        return bool(result.stdout) and result.returncode == 0

    def _wait_for_service(self):
        """Wait for the service to become ready.

        Raises:
            NotImplementedError: Subclasses must implement this.
        """
        raise NotImplementedError()

    def _test_connect_service(self):
        """Test if the service is running and responding.

        Returns:
            True if service is ready, False otherwise.

        Raises:
            NotImplementedError: Subclasses must implement this.
        """
        raise NotImplementedError()
