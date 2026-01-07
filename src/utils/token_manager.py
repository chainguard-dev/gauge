"""
Token refresh management for long-running scans.

Handles automatic token refresh for registries that require
authentication, preventing token expiration during long scans.
"""

import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from constants import CLI_SUBPROCESS_TIMEOUT, VERSION_CHECK_TIMEOUT, GCR_REGISTRIES, ARTIFACT_REGISTRY_SUFFIX

logger = logging.getLogger(__name__)


@dataclass
class TokenStatus:
    """Token validity status."""
    is_valid: bool
    expires_in: Optional[float]  # seconds until expiration
    needs_refresh: bool


class TokenManager:
    """
    Manages authentication tokens for container registries.

    Tracks token age and refreshes as needed for long scans.
    """

    def __init__(self, refresh_threshold: float = 900):  # 15 minutes
        """
        Initialize token manager.

        Args:
            refresh_threshold: Refresh tokens older than this (seconds)
        """
        self.refresh_threshold = refresh_threshold
        self.last_refresh_time: dict[str, float] = {}
        self.refresh_interval = 3600  # Refresh every hour for safety

    def needs_refresh(self, registry: str) -> bool:
        """
        Check if token for registry needs refresh.

        Args:
            registry: Registry hostname

        Returns:
            True if token should be refreshed
        """
        if registry not in self.last_refresh_time:
            # Never refreshed - for cgr.dev, proactively refresh to ensure token is fresh
            if isinstance(registry, str) and "cgr.dev" in registry:
                return True
            return False

        elapsed = time.time() - self.last_refresh_time[registry]
        return elapsed >= self.refresh_interval

    def refresh_chainguard_token(self) -> bool:
        """
        Refresh Chainguard registry token via chainctl.

        Returns:
            True if refresh succeeded
        """
        try:
            logger.info("Refreshing Chainguard authentication token...")

            # Check if chainctl is available
            check_result = subprocess.run(
                ["chainctl", "version"],
                capture_output=True,
                timeout=VERSION_CHECK_TIMEOUT
            )

            if check_result.returncode != 0:
                logger.debug("chainctl not available, skipping token refresh")
                return False

            # Get fresh token
            token_result = subprocess.run(
                ["chainctl", "auth", "token"],
                capture_output=True,
                timeout=CLI_SUBPROCESS_TIMEOUT
            )

            if token_result.returncode == 0:
                # Reconfigure Docker auth
                config_result = subprocess.run(
                    ["chainctl", "auth", "configure-docker"],
                    capture_output=True,
                    timeout=CLI_SUBPROCESS_TIMEOUT
                )

                if config_result.returncode == 0:
                    self.last_refresh_time["cgr.dev"] = time.time()
                    logger.info("✓ Chainguard token refreshed successfully")
                    return True
                else:
                    logger.warning("Failed to configure Docker auth after token refresh")
                    return False
            else:
                # Token expired, need to login
                logger.warning("Chainguard token expired, attempting login...")
                login_result = subprocess.run(
                    ["chainctl", "auth", "login"],
                    capture_output=True,
                    timeout=CLI_SUBPROCESS_TIMEOUT
                )

                if login_result.returncode == 0:
                    self.last_refresh_time["cgr.dev"] = time.time()
                    logger.info("✓ Chainguard authentication renewed")
                    return True
                else:
                    logger.error("Failed to refresh Chainguard authentication")
                    return False

        except subprocess.TimeoutExpired:
            logger.warning("Token refresh timed out")
            return False
        except FileNotFoundError:
            logger.debug("chainctl not found, skipping token refresh")
            return False
        except Exception as e:
            logger.warning(f"Token refresh failed: {e}")
            return False

    def refresh_gcr_token(self) -> bool:
        """
        Refresh Google Cloud Registry token.

        Returns:
            True if refresh succeeded
        """
        try:
            from utils.gcr_auth import GCRAuthenticator

            logger.info("Refreshing Google Cloud Registry authentication token...")
            gcr_auth = GCRAuthenticator()

            if gcr_auth.authenticate():
                # Record refresh for all GCR registries
                for registry in GCR_REGISTRIES:
                    self.last_refresh_time[registry] = time.time()
                self.last_refresh_time[ARTIFACT_REGISTRY_SUFFIX] = time.time()
                logger.info("GCR token refreshed successfully")
                return True
            else:
                logger.warning("Failed to refresh GCR authentication")
                return False

        except Exception as e:
            logger.warning(f"GCR token refresh failed: {e}")
            return False

    def _is_gcr_registry(self, registry: str) -> bool:
        """Check if registry is a GCR or Artifact Registry."""
        if not registry:
            return False
        for gcr_registry in GCR_REGISTRIES:
            if gcr_registry in registry:
                return True
        if ARTIFACT_REGISTRY_SUFFIX in registry:
            return True
        return False

    def refresh_if_needed(self, registry: str) -> bool:
        """
        Refresh token if needed for the given registry.

        Args:
            registry: Registry hostname

        Returns:
            True if token is valid (either fresh or successfully refreshed)
        """
        if not self.needs_refresh(registry):
            return True

        if isinstance(registry, str) and "cgr.dev" in registry:
            return self.refresh_chainguard_token()
        elif self._is_gcr_registry(registry):
            return self.refresh_gcr_token()
        else:
            # For other registries, we don't have automatic refresh
            logger.debug(f"No automatic token refresh available for {registry}")
            return True

    def record_scan_start(self, registry: str):
        """Record that we started scanning images from this registry."""
        if registry not in self.last_refresh_time:
            self.last_refresh_time[registry] = time.time()
