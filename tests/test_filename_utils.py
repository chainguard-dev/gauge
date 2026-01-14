"""Tests for filename utility functions."""

import pytest

from utils.filename_utils import extract_registry_from_image, sanitize_customer_name


class TestSanitizeCustomerName:
    """Tests for sanitize_customer_name function."""

    def test_simple_name(self):
        """Test simple customer name."""
        assert sanitize_customer_name("Acme") == "acme"

    def test_name_with_spaces(self):
        """Test name with spaces."""
        assert sanitize_customer_name("Acme Corp") == "acme_corp"

    def test_name_with_ampersand(self):
        """Test name with ampersand."""
        assert sanitize_customer_name("Test & Co") == "test_co"

    def test_name_with_dots(self):
        """Test name with dots."""
        assert sanitize_customer_name("Test.Company") == "testcompany"

    def test_name_with_special_chars(self):
        """Test name with various special characters."""
        assert sanitize_customer_name("Test@Company#Inc!") == "test_company_inc_"

    def test_name_with_multiple_spaces(self):
        """Test name with multiple consecutive spaces."""
        assert sanitize_customer_name("Test   Company") == "test_company"

    def test_name_with_hyphens(self):
        """Test name with hyphens (should be preserved)."""
        assert sanitize_customer_name("Test-Company") == "test-company"

    def test_name_with_underscores(self):
        """Test name with underscores (should be preserved)."""
        assert sanitize_customer_name("Test_Company") == "test_company"

    def test_mixed_case(self):
        """Test mixed case name."""
        assert sanitize_customer_name("TestCompany") == "testcompany"


class TestExtractRegistryFromImage:
    """Tests for extract_registry_from_image function."""

    def test_docker_hub_official_image(self):
        """Test official Docker Hub image (no registry prefix)."""
        assert extract_registry_from_image("nginx:latest") == "docker.io"

    def test_docker_hub_official_image_no_tag(self):
        """Test official Docker Hub image without tag."""
        assert extract_registry_from_image("nginx") == "docker.io"

    def test_docker_hub_user_image(self):
        """Test Docker Hub user image."""
        assert extract_registry_from_image("library/nginx:latest") == "docker.io"

    def test_docker_hub_org_image(self):
        """Test Docker Hub organization image."""
        assert extract_registry_from_image("myuser/myimage:v1") == "docker.io"

    def test_gcr_image(self):
        """Test Google Container Registry image."""
        assert extract_registry_from_image("gcr.io/myproject/myimage:latest") == "gcr.io"

    def test_ghcr_image(self):
        """Test GitHub Container Registry image."""
        assert extract_registry_from_image("ghcr.io/owner/image:v1.0") == "ghcr.io"

    def test_quay_image(self):
        """Test Quay.io image."""
        assert extract_registry_from_image("quay.io/organization/image:tag") == "quay.io"

    def test_ecr_image(self):
        """Test AWS ECR image."""
        assert extract_registry_from_image("123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag") == "123456789012.dkr.ecr.us-east-1.amazonaws.com"

    def test_iron_bank_image(self):
        """Test Iron Bank registry image."""
        assert extract_registry_from_image("registry1.dso.mil/ironbank/nginx:1.25") == "registry1.dso.mil"

    def test_private_registry_image(self):
        """Test private registry image."""
        assert extract_registry_from_image("myregistry.company.com/team/app:v2") == "myregistry.company.com"

    def test_localhost_image(self):
        """Test localhost registry image."""
        assert extract_registry_from_image("localhost/myimage:dev") == "localhost"

    def test_localhost_with_port(self):
        """Test localhost with port."""
        assert extract_registry_from_image("localhost:5000/myimage:dev") == "localhost:5000"

    def test_chainguard_image(self):
        """Test Chainguard registry image."""
        assert extract_registry_from_image("cgr.dev/chainguard/nginx:latest") == "cgr.dev"

    def test_image_with_digest(self):
        """Test image with digest instead of tag."""
        assert extract_registry_from_image("nginx@sha256:abc123def456") == "docker.io"

    def test_registry_image_with_digest(self):
        """Test registry image with digest."""
        assert extract_registry_from_image("gcr.io/project/image@sha256:abc123") == "gcr.io"

    def test_image_with_tag_and_digest(self):
        """Test image with both tag and digest (tag ignored)."""
        assert extract_registry_from_image("nginx:latest@sha256:abc123") == "docker.io"

    def test_alpine_jmeter(self):
        """Test alpine/jmeter format (Docker Hub org)."""
        assert extract_registry_from_image("alpine/jmeter:5") == "docker.io"

    def test_bitnami_image(self):
        """Test Bitnami image format."""
        assert extract_registry_from_image("bitnami/postgresql:15") == "docker.io"
