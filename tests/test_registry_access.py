"""Tests for registry access checking."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from utils.registry_access import (
    RegistryAccessChecker,
    DEFAULT_PUBLIC_REGISTRIES,
    IRON_BANK_REGISTRY,
)


class TestRegistryAccessChecker:
    """Tests for RegistryAccessChecker class."""

    def test_default_public_registries_accessible(self):
        """Test that default public registries are always accessible."""
        checker = RegistryAccessChecker()

        # All default public registries should be accessible
        for registry in DEFAULT_PUBLIC_REGISTRIES:
            image = f"{registry}/test/image:latest"
            assert checker.is_accessible(image), f"Expected {registry} to be accessible"

    def test_docker_hub_images_accessible(self):
        """Test that Docker Hub images (no registry prefix) are accessible."""
        checker = RegistryAccessChecker()

        # Images without registry prefix are Docker Hub
        assert checker.is_accessible("nginx:latest")
        assert checker.is_accessible("python:3.12")
        assert checker.is_accessible("library/nginx:latest")
        assert checker.is_accessible("myuser/myimage:v1")

    def test_unknown_registry_not_accessible(self):
        """Test that unknown registries are not accessible by default."""
        checker = RegistryAccessChecker()

        # Unknown private registries should not be accessible
        assert not checker.is_accessible("mycompany.io/image:latest")
        assert not checker.is_accessible("artifactory.internal.com/nginx:1.25")
        assert not checker.is_accessible("ecr.us-east-1.amazonaws.com/myapp:v1")

    def test_additional_registries_accessible(self):
        """Test that user-configured additional registries are accessible."""
        checker = RegistryAccessChecker(
            additional_registries=["mycompany.io", "internal.registry.com"]
        )

        # Configured registries should be accessible
        assert checker.is_accessible("mycompany.io/image:latest")
        assert checker.is_accessible("internal.registry.com/app:v1")

        # But other unknown registries still aren't
        assert not checker.is_accessible("other.company.io/image:latest")

    def test_additional_registries_case_insensitive(self):
        """Test that registry matching is case-insensitive."""
        checker = RegistryAccessChecker(
            additional_registries=["MyCompany.IO"]
        )

        assert checker.is_accessible("mycompany.io/image:latest")
        assert checker.is_accessible("MYCOMPANY.IO/image:latest")

    @patch('utils.registry_access.image_exists_in_registry')
    def test_iron_bank_accessible_with_credentials(self, mock_exists):
        """Test that Iron Bank is accessible when credentials are valid."""
        mock_exists.return_value = True

        checker = RegistryAccessChecker()
        result = checker.is_accessible("registry1.dso.mil/ironbank/python:3.12")

        assert result is True
        mock_exists.assert_called_once()

    @patch('utils.registry_access.image_exists_in_registry')
    def test_iron_bank_not_accessible_without_credentials(self, mock_exists):
        """Test that Iron Bank is not accessible when credentials fail."""
        mock_exists.return_value = False

        checker = RegistryAccessChecker()
        result = checker.is_accessible("registry1.dso.mil/ironbank/python:3.12")

        assert result is False

    @patch('utils.registry_access.image_exists_in_registry')
    def test_iron_bank_access_cached(self, mock_exists):
        """Test that Iron Bank access status is cached after first check."""
        mock_exists.return_value = True

        checker = RegistryAccessChecker()

        # First check should call image_exists_in_registry
        result1 = checker.is_accessible("registry1.dso.mil/ironbank/python:3.12")
        assert result1 is True
        assert mock_exists.call_count == 1

        # Second check should use cached result
        result2 = checker.is_accessible("registry1.dso.mil/ironbank/nginx:1.25")
        assert result2 is True
        assert mock_exists.call_count == 1  # Still just 1 call

    def test_extract_registry_docker_hub(self):
        """Test registry extraction for Docker Hub images."""
        checker = RegistryAccessChecker()

        assert checker._extract_registry("nginx:latest") is None
        assert checker._extract_registry("library/nginx") is None
        assert checker._extract_registry("myuser/myimage") is None

    def test_extract_registry_with_prefix(self):
        """Test registry extraction for images with registry prefix."""
        checker = RegistryAccessChecker()

        assert checker._extract_registry("gcr.io/project/image") == "gcr.io"
        assert checker._extract_registry("registry1.dso.mil/ironbank/python") == "registry1.dso.mil"
        assert checker._extract_registry("mycompany.io/app:v1") == "mycompany.io"
        assert checker._extract_registry("localhost:5000/image") == "localhost:5000"
        assert checker._extract_registry("localhost/image") == "localhost"

    def test_get_registry_display_name(self):
        """Test get_registry returns human-readable registry name."""
        checker = RegistryAccessChecker()

        assert checker.get_registry("nginx:latest") == "Docker Hub"
        assert checker.get_registry("gcr.io/project/image") == "gcr.io"
        assert checker.get_registry("registry1.dso.mil/ironbank/python") == "registry1.dso.mil"

    def test_registry_access_cache(self):
        """Test that registry access results are cached."""
        checker = RegistryAccessChecker()

        # First check - not in cache
        result1 = checker.is_accessible("gcr.io/project/image")
        assert result1 is True

        # Second check - should use cache
        result2 = checker.is_accessible("gcr.io/other-project/other-image")
        assert result2 is True

        # Cache key should be the registry, not the full image
        assert "gcr.io" in checker._access_cache

    def test_config_file_loading_yaml(self, tmp_path):
        """Test loading additional registries from YAML config file."""
        config_file = tmp_path / "registries.yaml"
        config_file.write_text("""
registries:
  - my.registry.com
  - another.registry.io
""")

        checker = RegistryAccessChecker(config_file=config_file)

        assert checker.is_accessible("my.registry.com/image:latest")
        assert checker.is_accessible("another.registry.io/app:v1")
        assert not checker.is_accessible("unknown.registry.com/image:latest")

    def test_config_file_loading_txt(self, tmp_path):
        """Test loading additional registries from text config file."""
        config_file = tmp_path / "registries.txt"
        config_file.write_text("""# Comment line
my.registry.com
another.registry.io

# Another comment
third.registry.net
""")

        checker = RegistryAccessChecker(config_file=config_file)

        assert checker.is_accessible("my.registry.com/image:latest")
        assert checker.is_accessible("another.registry.io/app:v1")
        assert checker.is_accessible("third.registry.net/app:v1")
        assert not checker.is_accessible("unknown.registry.com/image:latest")

    def test_config_file_not_found(self, tmp_path):
        """Test graceful handling of missing config file."""
        checker = RegistryAccessChecker(
            config_file=tmp_path / "nonexistent.yaml"
        )

        # Should still work with default registries
        assert checker.is_accessible("docker.io/library/nginx")

    def test_default_config_file_path(self):
        """Test that default config file path is set correctly."""
        assert RegistryAccessChecker.DEFAULT_CONFIG_FILE == Path("config/known_registries.txt")

    @patch('utils.registry_access.image_exists_in_registry')
    def test_iron_bank_access_check_exception_handling(self, mock_exists):
        """Test that exceptions during Iron Bank access check are handled."""
        mock_exists.side_effect = Exception("Network error")

        checker = RegistryAccessChecker()
        result = checker.is_accessible("registry1.dso.mil/ironbank/python:3.12")

        # Should treat exception as inaccessible
        assert result is False


class TestPublicRegistryList:
    """Tests for the default public registry list."""

    def test_common_registries_included(self):
        """Test that common public registries are in the default list."""
        expected = [
            "docker.io",
            "gcr.io",
            "ghcr.io",
            "quay.io",
            "registry.k8s.io",
            "mcr.microsoft.com",
            "public.ecr.aws",
        ]

        for registry in expected:
            assert registry in DEFAULT_PUBLIC_REGISTRIES

    def test_iron_bank_constant(self):
        """Test Iron Bank registry constant is correct."""
        assert IRON_BANK_REGISTRY == "registry1.dso.mil"
