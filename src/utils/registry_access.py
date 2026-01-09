"""
Registry access checking for determining when upstream discovery is needed.

This module determines whether an image's source registry is "known and accessible",
meaning we can pull from it directly without needing to find a public upstream equivalent.
"""

import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

from utils.docker_utils import image_exists_in_registry

logger = logging.getLogger(__name__)

# Default public registries that are always considered accessible
DEFAULT_PUBLIC_REGISTRIES = frozenset({
    "docker.io",
    "registry-1.docker.io",  # Docker Hub's actual domain
    "index.docker.io",
    "gcr.io",
    "ghcr.io",
    "quay.io",
    "registry.k8s.io",
    "k8s.gcr.io",
    "mcr.microsoft.com",
    "public.ecr.aws",
    "docker.elastic.co",
    "registry.access.redhat.com",
})

# Iron Bank registry - requires special credential check
IRON_BANK_REGISTRY = "registry1.dso.mil"


class RegistryAccessChecker:
    """
    Checks if an image's registry is known and accessible.

    Used to determine whether upstream discovery should be skipped.
    If a registry is accessible, we can match the image directly without
    finding a public upstream equivalent.
    """

    # Default config file path
    DEFAULT_CONFIG_FILE = Path("config/known_registries.txt")

    def __init__(
        self,
        additional_registries: Optional[list[str]] = None,
        config_file: Optional[Path] = None,
    ):
        """
        Initialize registry access checker.

        Args:
            additional_registries: Additional registries the user has credentials for
            config_file: Optional config file with known registries (supports .txt and .yaml)
        """
        self.known_registries = set(DEFAULT_PUBLIC_REGISTRIES)

        # Add user-configured registries
        if additional_registries:
            for reg in additional_registries:
                reg = reg.strip().lower()
                if reg:
                    self.known_registries.add(reg)
                    logger.debug(f"Added known registry: {reg}")

        # Load from config file (use default if not specified)
        config_path = config_file if config_file else self.DEFAULT_CONFIG_FILE
        if config_path.exists():
            self._load_config_file(config_path)

        # Cache for Iron Bank access status (checked once per session)
        self._iron_bank_accessible: Optional[bool] = None

        # Cache for registry access checks (avoid repeated checks)
        self._access_cache: dict[str, bool] = {}

    def _load_config_file(self, config_file: Path) -> None:
        """
        Load additional registries from config file.

        Supports two formats:
        - .txt: One registry per line (lines starting with # are comments)
        - .yaml/.yml: YAML with 'registries' list
        """
        try:
            suffix = config_file.suffix.lower()

            if suffix == ".txt":
                self._load_text_config(config_file)
            elif suffix in (".yaml", ".yml"):
                self._load_yaml_config(config_file)
            else:
                # Default to text format for unknown extensions
                self._load_text_config(config_file)
        except Exception as e:
            logger.warning(f"Failed to load registry config from {config_file}: {e}")

    def _load_text_config(self, config_file: Path) -> None:
        """Load registries from text file (one per line, # for comments)."""
        count = 0
        with open(config_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                self.known_registries.add(line.lower())
                count += 1

        if count > 0:
            logger.info(f"Loaded {count} known registries from {config_file}")

    def _load_yaml_config(self, config_file: Path) -> None:
        """Load registries from YAML config file."""
        import yaml
        with open(config_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if data and isinstance(data, dict):
            registries = data.get("registries", [])
            if isinstance(registries, list):
                count = 0
                for reg in registries:
                    if isinstance(reg, str) and reg.strip():
                        self.known_registries.add(reg.strip().lower())
                        count += 1
                if count > 0:
                    logger.info(f"Loaded {count} known registries from {config_file}")

    def is_accessible(self, image: str) -> bool:
        """
        Check if an image's registry is known and accessible.

        Args:
            image: Full image reference (e.g., registry1.dso.mil/ironbank/nginx:1.21)

        Returns:
            True if the registry is accessible (skip upstream discovery),
            False if we should try to find a public upstream equivalent
        """
        registry = self._extract_registry(image)

        # Check cache first
        cache_key = registry or "docker.io"
        if cache_key in self._access_cache:
            return self._access_cache[cache_key]

        # No registry prefix = Docker Hub (always accessible)
        if registry is None:
            self._access_cache[cache_key] = True
            return True

        registry_lower = registry.lower()

        # Public registries are always accessible
        if registry_lower in self.known_registries:
            logger.debug(f"Registry {registry} is a known public registry")
            self._access_cache[cache_key] = True
            return True

        # Iron Bank requires credential check
        if registry_lower == IRON_BANK_REGISTRY:
            accessible = self._check_iron_bank_access(image)
            self._access_cache[cache_key] = accessible
            return accessible

        # Unknown registry - assume inaccessible (will try upstream discovery)
        logger.debug(f"Registry {registry} is unknown, will try upstream discovery")
        self._access_cache[cache_key] = False
        return False

    def _extract_registry(self, image: str) -> Optional[str]:
        """
        Extract registry from image reference.

        Args:
            image: Full image reference

        Returns:
            Registry hostname, or None if no registry (Docker Hub)
        """
        # Handle images without registry prefix (Docker Hub)
        if "/" not in image:
            return None

        first_part = image.split("/")[0]

        # Check if first part looks like a registry (has dot or colon, or is localhost)
        if "." in first_part or ":" in first_part or first_part == "localhost":
            return first_part

        # No registry prefix (e.g., "library/nginx" or "user/image")
        return None

    def _check_iron_bank_access(self, image: str) -> bool:
        """
        Check if Iron Bank registry is accessible with current credentials.

        Args:
            image: Iron Bank image reference

        Returns:
            True if accessible, False otherwise
        """
        # Use cached result if available
        if self._iron_bank_accessible is not None:
            if self._iron_bank_accessible:
                logger.debug("Iron Bank access confirmed (cached)")
            return self._iron_bank_accessible

        logger.debug("Checking Iron Bank registry access...")

        # Check if we have Docker credentials for Iron Bank
        # Try to verify the image exists (this will use Docker's credential chain)
        try:
            accessible = image_exists_in_registry(image, timeout=10)
            if accessible:
                logger.info(
                    f"Iron Bank registry accessible - will use Iron Bank images directly"
                )
                self._iron_bank_accessible = True
                return True
        except Exception as e:
            logger.debug(f"Iron Bank access check failed: {e}")

        # Iron Bank not accessible - will need upstream discovery
        logger.warning(
            f"Iron Bank registry ({IRON_BANK_REGISTRY}) not accessible.\n"
            f"  To use Iron Bank images directly, configure Docker credentials:\n"
            f"    docker login {IRON_BANK_REGISTRY}\n"
            f"  Will attempt to find public upstream alternatives instead."
        )
        self._iron_bank_accessible = False
        return False

    def get_registry(self, image: str) -> str:
        """
        Get the registry for an image (for logging/display).

        Args:
            image: Full image reference

        Returns:
            Registry name or "Docker Hub" if no registry prefix
        """
        registry = self._extract_registry(image)
        return registry if registry else "Docker Hub"
