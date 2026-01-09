"""
Centralized image verification service.

Provides unified verification for Chainguard images with configurable strategies:
- GitHub metadata API (fast, but requires token)
- Docker registry manifest inspection (slower, but always works)
"""

import logging
from typing import Optional

from constants import CHAINGUARD_PRIVATE_REGISTRY, CHAINGUARD_PUBLIC_REGISTRY
from integrations.github_metadata import GitHubMetadataClient

logger = logging.getLogger(__name__)


class ImageVerificationService:
    """
    Centralized service for verifying Chainguard image existence.

    Uses a two-tier verification strategy:
    1. GitHub metadata API (fast, preferred)
    2. Docker manifest inspect (fallback)

    Results are cached in-memory to avoid redundant verification calls.
    """

    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize image verification service.

        Args:
            github_token: Optional GitHub token for metadata API access
        """
        self.github_metadata = GitHubMetadataClient(github_token=github_token)
        # In-memory cache for verification results (per instance)
        self._verification_cache: dict[str, bool] = {}

    def verify_image_exists(
        self,
        image: str,
        prefer_github_api: bool = True
    ) -> bool:
        """
        Verify if a Chainguard image exists.

        Args:
            image: Full image reference (e.g., cgr.dev/chainguard/python:latest)
            prefer_github_api: If True, try GitHub API before Docker fallback

        Returns:
            True if image exists, False otherwise
        """
        # Check in-memory cache first
        if image in self._verification_cache:
            logger.debug(f"Cache hit for image verification: {image}")
            return self._verification_cache[image]

        # Only verify Chainguard images
        if not self._is_chainguard_image(image):
            logger.debug(f"Image {image} is not a Chainguard image")
            self._verification_cache[image] = False
            return False

        image_name = self._extract_image_name(image)
        if not image_name:
            logger.debug(f"Could not extract image name from {image}")
            self._verification_cache[image] = False
            return False

        # Try GitHub API first (if preferred)
        if prefer_github_api:
            if self._verify_via_github_api(image_name):
                self._verification_cache[image] = True
                return True

        # Fallback to Docker manifest inspection
        result = self._verify_via_docker(image)
        self._verification_cache[image] = result
        return result

    def _is_chainguard_image(self, image: str) -> bool:
        """Check if image is from Chainguard registry."""
        return (
            image.startswith(f"{CHAINGUARD_PRIVATE_REGISTRY}/") or
            image.startswith(f"{CHAINGUARD_PUBLIC_REGISTRY}/")
        )

    def _extract_image_name(self, image: str) -> Optional[str]:
        """
        Extract image name from full reference.

        Example:
            cgr.dev/chainguard/python:latest → python
            cgr.dev/chainguard-private/nginx:1.21 → nginx

        Returns:
            Image name without registry, tag, or digest
        """
        parts = image.split("/")
        if len(parts) >= 3:
            # Get the image name (last part before tag/digest)
            image_with_tag = parts[2]
            # Remove tag and digest
            name = image_with_tag.split(":")[0].split("@")[0]
            return name
        return None

    def _verify_via_github_api(self, image_name: str) -> bool:
        """
        Verify image via GitHub metadata API.

        Args:
            image_name: Name of the image (without registry/tag)

        Returns:
            True if verified, False if verification failed
        """
        try:
            tier = self.github_metadata.get_image_tier(image_name)
            if tier is not None:
                logger.debug(f"GitHub API confirmed image exists: {image_name} (tier: {tier})")
                return True
        except Exception as e:
            logger.debug(f"GitHub metadata not found for {image_name}: {e}")

        return False

    def _verify_via_docker(self, image: str) -> bool:
        """
        Verify image via Docker manifest inspection.

        Args:
            image: Full image reference

        Returns:
            True if verified, False if verification failed
        """
        logger.debug(f"Falling back to Docker verification for {image}")

        # Import here to avoid circular dependency
        from utils.docker_utils import image_exists_in_registry

        try:
            exists = image_exists_in_registry(image)
            if exists:
                logger.debug(f"Docker manifest confirmed image exists: {image}")
            return exists
        except Exception as e:
            logger.debug(f"Docker verification failed for {image}: {e}")
            return False
