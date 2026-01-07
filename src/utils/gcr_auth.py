"""
Google Cloud Registry (GCR) authentication utilities.

Provides authentication support for pulling images from:
- Google Container Registry (gcr.io, us.gcr.io, eu.gcr.io, asia.gcr.io)
- Google Artifact Registry (*.pkg.dev)
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

from constants import GCR_AUTH_TIMEOUT

logger = logging.getLogger(__name__)

# Registry patterns that require GCR authentication
GCR_REGISTRY_PATTERNS = ["gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io"]
ARTIFACT_REGISTRY_SUFFIX = "pkg.dev"


class GCRAuthenticator:
    """
    Handles authentication to Google Cloud Registry (GCR) and Artifact Registry.

    Authentication priority:
    1. Explicit credentials file (CLI flag)
    2. GOOGLE_APPLICATION_CREDENTIALS environment variable
    3. gcloud Application Default Credentials (ADC)
    """

    def __init__(self, credentials_file: Optional[Path] = None):
        """
        Initialize GCR authenticator.

        Args:
            credentials_file: Optional path to service account JSON file (CLI flag)
        """
        self.credentials_file = credentials_file

    def is_gcr_registry(self, image: str) -> bool:
        """
        Check if an image is from a GCR or Artifact Registry.

        Args:
            image: Container image reference

        Returns:
            True if image requires GCR authentication
        """
        if not image:
            return False

        # Public mirror doesn't require auth
        if "mirror.gcr.io" in image:
            return False

        # Check GCR patterns
        for pattern in GCR_REGISTRY_PATTERNS:
            if image.startswith(f"{pattern}/") or f"/{pattern}/" in image:
                return True

        # Check Artifact Registry
        if ARTIFACT_REGISTRY_SUFFIX in image:
            return True

        return False

    def authenticate(self) -> bool:
        """
        Attempt to configure GCR authentication.

        Tries authentication methods in priority order:
        1. Explicit credentials file (from CLI flag)
        2. GOOGLE_APPLICATION_CREDENTIALS environment variable
        3. gcloud Application Default Credentials

        Returns:
            True if authentication was successfully configured
        """
        # Priority 1: Explicit credentials file from CLI
        if self.credentials_file:
            if self._auth_with_service_account(self.credentials_file):
                return True
            logger.warning(f"Failed to authenticate with provided credentials: {self.credentials_file}")
            return False

        # Priority 2: GOOGLE_APPLICATION_CREDENTIALS env var
        env_creds = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        if env_creds:
            creds_path = Path(env_creds)
            if creds_path.exists():
                if self._auth_with_service_account(creds_path):
                    return True
                logger.warning(f"Failed to authenticate with GOOGLE_APPLICATION_CREDENTIALS: {env_creds}")
            else:
                logger.warning(f"GOOGLE_APPLICATION_CREDENTIALS file not found: {env_creds}")

        # Priority 3: gcloud ADC
        if self._auth_with_gcloud_adc():
            return True

        return False

    def _auth_with_service_account(self, credentials_file: Path) -> bool:
        """
        Authenticate using a service account JSON file.

        Args:
            credentials_file: Path to service account JSON file

        Returns:
            True if authentication succeeded
        """
        try:
            # Validate JSON file
            with open(credentials_file, "r") as f:
                creds = json.load(f)

            if "client_email" not in creds or "private_key" not in creds:
                logger.error("Invalid service account JSON: missing required fields")
                return False

            # Get access token using gcloud
            result = subprocess.run(
                [
                    "gcloud", "auth", "activate-service-account",
                    "--key-file", str(credentials_file),
                    "--quiet"
                ],
                capture_output=True,
                text=True,
                timeout=GCR_AUTH_TIMEOUT
            )

            if result.returncode != 0:
                logger.debug(f"Service account activation failed: {result.stderr}")
                # Fall back to getting access token directly
                return self._configure_docker_with_service_account(credentials_file)

            # Configure Docker
            return self._configure_docker_registries()

        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in credentials file: {credentials_file}")
            return False
        except FileNotFoundError:
            logger.error(f"Credentials file not found: {credentials_file}")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("GCR authentication timed out")
            return False
        except Exception as e:
            logger.warning(f"Service account authentication failed: {e}")
            return False

    def _configure_docker_with_service_account(self, credentials_file: Path) -> bool:
        """
        Configure Docker credentials directly from service account.

        Args:
            credentials_file: Path to service account JSON file

        Returns:
            True if configuration succeeded
        """
        try:
            # Get access token using the service account
            result = subprocess.run(
                [
                    "gcloud", "auth", "print-access-token",
                    "--credential-file-override", str(credentials_file)
                ],
                capture_output=True,
                text=True,
                timeout=GCR_AUTH_TIMEOUT
            )

            if result.returncode != 0:
                logger.debug(f"Failed to get access token: {result.stderr}")
                return False

            access_token = result.stdout.strip()
            return self._configure_docker_credentials(access_token)

        except subprocess.TimeoutExpired:
            logger.warning("Access token retrieval timed out")
            return False
        except Exception as e:
            logger.warning(f"Failed to configure Docker with service account: {e}")
            return False

    def _auth_with_gcloud_adc(self) -> bool:
        """
        Authenticate using gcloud Application Default Credentials.

        Returns:
            True if authentication succeeded
        """
        try:
            # Check if gcloud is available
            check_result = subprocess.run(
                ["gcloud", "version"],
                capture_output=True,
                timeout=5
            )

            if check_result.returncode != 0:
                logger.debug("gcloud not available")
                return False

            # Try to get access token using ADC
            result = subprocess.run(
                ["gcloud", "auth", "print-access-token"],
                capture_output=True,
                text=True,
                timeout=GCR_AUTH_TIMEOUT
            )

            if result.returncode != 0:
                # Check if user is logged in
                logger.debug(f"gcloud auth print-access-token failed: {result.stderr}")
                return False

            access_token = result.stdout.strip()
            if not access_token:
                logger.debug("No access token returned from gcloud")
                return False

            return self._configure_docker_credentials(access_token)

        except FileNotFoundError:
            logger.debug("gcloud not found")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("gcloud ADC authentication timed out")
            return False
        except Exception as e:
            logger.warning(f"gcloud ADC authentication failed: {e}")
            return False

    def _configure_docker_credentials(self, access_token: str) -> bool:
        """
        Configure Docker with GCR access token.

        Args:
            access_token: OAuth2 access token for GCR

        Returns:
            True if configuration succeeded
        """
        registries = GCR_REGISTRY_PATTERNS + [ARTIFACT_REGISTRY_SUFFIX]
        success = False

        for registry in registries:
            try:
                result = subprocess.run(
                    [
                        "docker", "login",
                        "-u", "oauth2accesstoken",
                        "-p", access_token,
                        f"https://{registry}"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=GCR_AUTH_TIMEOUT
                )

                if result.returncode == 0:
                    success = True
                    logger.debug(f"Configured Docker credentials for {registry}")
                else:
                    logger.debug(f"Docker login failed for {registry}: {result.stderr}")

            except Exception as e:
                logger.debug(f"Failed to configure Docker for {registry}: {e}")

        return success

    def _configure_docker_registries(self) -> bool:
        """
        Configure Docker for GCR registries using gcloud.

        Returns:
            True if configuration succeeded
        """
        try:
            # Use gcloud auth configure-docker for all GCR registries
            registries_arg = ",".join(GCR_REGISTRY_PATTERNS)
            result = subprocess.run(
                ["gcloud", "auth", "configure-docker", registries_arg, "--quiet"],
                capture_output=True,
                text=True,
                timeout=GCR_AUTH_TIMEOUT
            )

            if result.returncode == 0:
                logger.debug("Configured Docker credentials for GCR registries")
                return True
            else:
                logger.debug(f"gcloud auth configure-docker failed: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logger.warning("Docker registry configuration timed out")
            return False
        except Exception as e:
            logger.warning(f"Failed to configure Docker registries: {e}")
            return False

    def get_access_token(self) -> Optional[str]:
        """
        Get a fresh GCR access token.

        Returns:
            Access token string or None if unavailable
        """
        try:
            result = subprocess.run(
                ["gcloud", "auth", "print-access-token"],
                capture_output=True,
                text=True,
                timeout=GCR_AUTH_TIMEOUT
            )

            if result.returncode == 0:
                return result.stdout.strip()

        except Exception as e:
            logger.debug(f"Failed to get access token: {e}")

        return None
