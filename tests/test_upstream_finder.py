"""
Tests for upstream image discovery functionality.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from utils.upstream_finder import UpstreamImageFinder, UpstreamResult


class TestUpstreamImageFinder:
    """Test upstream image finder with 4-strategy approach."""

    @pytest.fixture
    def mock_upstream_mappings(self):
        """Mock upstream mappings YAML content."""
        return """
"company.io/python-app:v1": "python:3.12"
"internal-nginx:prod": "nginx:1.25"
"gcr.io/myproject/redis:latest": "redis:7.0"
"""

    @pytest.fixture
    def upstream_finder(self, tmp_path, mock_upstream_mappings):
        """Create UpstreamImageFinder with mocked mappings."""
        mappings_file = tmp_path / "upstream_mappings.yaml"
        mappings_file.write_text(mock_upstream_mappings)

        return UpstreamImageFinder(
            manual_mappings_file=mappings_file,
            min_confidence=0.7,
        )

    def test_manual_mapping(self, upstream_finder):
        """Test Strategy 1: Manual mappings (100% confidence)."""
        result = upstream_finder.find_upstream("company.io/python-app:v1")

        assert result.upstream_image == "python:3.12"
        assert result.confidence == 1.0
        assert result.method == "manual"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_registry_strip_success(self, mock_exists, tmp_path):
        """Test Strategy 2: Registry strip (90% confidence)."""
        # Create finder without manual mappings
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock verification to return True
        mock_exists.return_value = True

        result = finder.find_upstream("mycompany.io/python:3.12")

        assert result.upstream_image == "python:3.12"
        assert result.confidence == 0.90
        assert result.method == "registry_strip"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_registry_strip_gcr(self, mock_exists, tmp_path):
        """Test registry strip with GCR private registry."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock: First try (full path myproject/nginx) fails, second try (nginx only) succeeds
        mock_exists.side_effect = [False, False, True]

        result = finder.find_upstream("gcr.io/myproject/nginx:latest")

        assert result.upstream_image == "nginx:latest"
        assert result.confidence == 0.85
        assert result.method == "registry_strip"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_registry_strip_ecr(self, mock_exists, tmp_path):
        """Test registry strip with AWS ECR."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        mock_exists.return_value = True

        result = finder.find_upstream("123456789.dkr.ecr.us-east-1.amazonaws.com/postgres:16")

        assert result.upstream_image == "postgres:16"
        assert result.confidence == 0.90
        assert result.method == "registry_strip"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_common_registry_dockerhub(self, mock_exists, tmp_path):
        """Test Strategy 3: Common registries (80% confidence) - Docker Hub."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock: First registry check succeeds
        mock_exists.return_value = True

        result = finder.find_upstream("custom-python:v1")

        assert result.upstream_image == "docker.io/library/custom-python"
        assert result.confidence == 0.80
        assert result.method == "common_registry"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_common_registry_quay(self, mock_exists, tmp_path):
        """Test common registries - Quay.io fallback."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock: First two fail, quay.io succeeds
        mock_exists.side_effect = [False, False, True]

        result = finder.find_upstream("custom-app:latest")

        assert result.upstream_image == "quay.io/custom-app"
        assert result.confidence == 0.80
        assert result.method == "common_registry"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_base_extraction_python(self, mock_exists, tmp_path):
        """Test Strategy 4: Base extraction (70% confidence) - Python."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock verification: Return False for common registries, True only for python base image
        def mock_verify(image: str) -> bool:
            return "library/python" in image or image == "docker.io/python:latest"

        mock_exists.side_effect = mock_verify

        result = finder.find_upstream("internal-python-app:v1")

        assert result.upstream_image == "python:latest"
        assert result.confidence == 0.70
        assert result.method == "base_extract"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_base_extraction_nginx(self, mock_exists, tmp_path):
        """Test base extraction - Nginx."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock verification: Return False for common registries, True only for nginx base image
        def mock_verify(image: str) -> bool:
            return "library/nginx" in image or image == "docker.io/nginx:latest"

        mock_exists.side_effect = mock_verify

        result = finder.find_upstream("company-nginx-prod:latest")

        assert result.upstream_image == "nginx:latest"
        assert result.confidence == 0.70
        assert result.method == "base_extract"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_base_extraction_postgres(self, mock_exists, tmp_path):
        """Test base extraction - Postgres."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock verification: Return False for common registries, True only for postgres base image
        def mock_verify(image: str) -> bool:
            return "library/postgres" in image or image == "docker.io/postgres:latest"

        mock_exists.side_effect = mock_verify

        result = finder.find_upstream("my-postgres-db:v2")

        assert result.upstream_image == "postgres:latest"
        assert result.confidence == 0.70
        assert result.method == "base_extract"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_no_match_found(self, mock_exists, tmp_path):
        """Test when no upstream is found."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock all verifications to fail
        mock_exists.return_value = False

        result = finder.find_upstream("completely-custom-app:v1")

        assert result.upstream_image is None
        assert result.confidence == 0.0
        assert result.method == "none"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_confidence_threshold_filtering(self, mock_exists, tmp_path):
        """Test that results below min_confidence are filtered."""
        # Set high threshold (0.85) that excludes base extraction (0.70)
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.85,
        )

        mock_exists.return_value = True

        result = finder.find_upstream("internal-python-app:v1")

        # Base extraction has 0.70 confidence, below 0.85 threshold
        assert result.upstream_image is None
        assert result.confidence == 0.0
        assert result.method == "none"

    def test_extract_base_name(self, tmp_path):
        """Test base name extraction utility."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
        )

        assert finder._extract_base_name("mycompany.io/python:3.12") == "python"
        assert finder._extract_base_name("gcr.io/project/nginx:latest") == "nginx"
        assert finder._extract_base_name("postgres:16") == "postgres"
        assert finder._extract_base_name("python") == "python"
        assert finder._extract_base_name("app:tag@sha256:abc123") == "app"

    def test_extract_full_path(self, tmp_path):
        """Test full path extraction utility (preserves org/image structure)."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
        )

        # Should preserve org/image structure
        assert finder._extract_full_path("kaniko-project/executor:v1.0") == "kaniko-project/executor"
        assert finder._extract_full_path("kaniko-project/executor") == "kaniko-project/executor"

        # Should strip registry prefix
        assert finder._extract_full_path("gcr.io/kaniko-project/executor") == "kaniko-project/executor"
        assert finder._extract_full_path("docker.io/library/nginx:latest") == "nginx"
        assert finder._extract_full_path("quay.io/prometheus/prometheus:v2.45.0") == "prometheus/prometheus"

        # Simple images (no org)
        assert finder._extract_full_path("nginx:latest") == "nginx"
        assert finder._extract_full_path("python") == "python"

        # With digest
        assert finder._extract_full_path("org/image@sha256:abc123") == "org/image"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_common_registry_gcr_full_path(self, mock_exists, tmp_path):
        """Test gcr.io registry with full path preserved (kaniko-project/executor case)."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock: First 4 registries (docker.io/library, docker.io, quay.io, ghcr.io) fail
        # gcr.io/kaniko-project/executor succeeds
        def mock_verify(image: str) -> bool:
            return image == "gcr.io/kaniko-project/executor"

        mock_exists.side_effect = mock_verify

        result = finder.find_upstream("kaniko-project/executor")

        assert result.upstream_image == "gcr.io/kaniko-project/executor"
        assert result.confidence == 0.80
        assert result.method == "common_registry"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_common_registry_tries_full_path_first(self, mock_exists, tmp_path):
        """Test that full path is tried before base name in common registries."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        call_order = []

        def track_calls(image: str) -> bool:
            call_order.append(image)
            # Only succeed for the gcr.io full path version
            return image == "gcr.io/myorg/myimage"

        mock_exists.side_effect = track_calls

        result = finder.find_upstream("myorg/myimage")

        # Should find it at gcr.io with full path
        assert result.upstream_image == "gcr.io/myorg/myimage"
        assert result.confidence == 0.80

        # Verify full path is tried before base name for each registry
        # docker.io/library should try full path first
        assert "docker.io/library/myorg/myimage" in call_order
        # docker.io should try full path
        assert "docker.io/myorg/myimage" in call_order

    def test_manual_mappings_loading_missing_file(self, tmp_path):
        """Test manual mappings loading when file doesn't exist."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
        )

        assert len(finder.manual_mappings) == 0

    def test_manual_mappings_loading_empty_file(self, tmp_path):
        """Test manual mappings loading when file is empty."""
        mappings_file = tmp_path / "empty.yaml"
        mappings_file.write_text("")

        finder = UpstreamImageFinder(manual_mappings_file=mappings_file)

        assert len(finder.manual_mappings) == 0

    def test_manual_mappings_priority(self, upstream_finder):
        """Test that manual mappings take precedence over automatic discovery."""
        # Even if automatic discovery would find something,
        # manual mapping should be returned
        result = upstream_finder.find_upstream("internal-nginx:prod")

        assert result.upstream_image == "nginx:1.25"
        assert result.confidence == 1.0
        assert result.method == "manual"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_strategy_fallback_order(self, mock_exists, tmp_path):
        """Test that strategies are tried in correct order."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock: All verification attempts fail
        mock_exists.return_value = False

        result = finder.find_upstream("mycompany.io/special-app:v1")

        # Should fall back to unverified registry strip (70% confidence)
        assert result.confidence == 0.70
        assert result.method == "registry_strip_unverified"
        assert result.upstream_image == "special-app:v1"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_verification_error_handling(self, mock_exists, tmp_path):
        """Test handling of verification errors."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock verification to raise exception
        mock_exists.side_effect = Exception("Registry error")

        result = finder.find_upstream("some-image:latest")

        # Should handle error gracefully and return no match
        assert result.upstream_image is None
        assert result.confidence == 0.0
        assert result.method == "none"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_node_exporter_not_matched_to_node(self, mock_exists, tmp_path):
        """Test that node-exporter does NOT match to Node.js 'node' image (issue #14)."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )
        mock_exists.return_value = False

        result = finder.find_upstream("prometheus/node-exporter:v1.10.2")

        # Should NOT extract "node" - exporter suffix indicates derivative tool
        assert result.upstream_image is None or result.upstream_image != "node:latest"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_redis_exporter_not_matched_to_redis(self, mock_exists, tmp_path):
        """Test that redis-exporter does NOT match to base 'redis' image (issue #14)."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )
        mock_exists.return_value = False

        result = finder.find_upstream("bitnami/analytics/redis-exporter:v1.80.1")

        # Should NOT extract "redis" - exporter suffix indicates derivative tool
        assert result.upstream_image is None or result.upstream_image != "redis:latest"

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_kafka_operator_not_matched_to_kafka(self, mock_exists, tmp_path):
        """Test that kafka-operator does NOT match to base 'kafka' image."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )
        mock_exists.return_value = False

        result = finder.find_upstream("strimzi/kafka-operator:latest")

        # Should NOT extract "kafka" - operator suffix indicates derivative tool
        assert result.upstream_image is None or result.upstream_image != "kafka:latest"

    # Note: Iron Bank-specific tests were removed as this logic is now in
    # RegistryAccessChecker (src/utils/registry_access.py). See test_registry_access.py
    # for Iron Bank access checking tests.

    @patch('utils.upstream_finder.image_exists_in_registry')
    def test_postgres_controller_not_matched_to_postgres(self, mock_exists, tmp_path):
        """Test that postgres-controller does NOT match to base 'postgres' image."""
        finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )
        mock_exists.return_value = False

        result = finder.find_upstream("zalando/postgres-controller:latest")

        # Should NOT extract "postgres" - controller suffix indicates derivative tool
        assert result.upstream_image is None or result.upstream_image != "postgres:latest"


class TestUpstreamFinderIntegration:
    """Integration tests for upstream finder with ImageMatcher."""

    @patch('utils.upstream_finder.image_exists_in_registry')
    @patch('utils.image_matcher.Tier3HeuristicMatcher._verify_image_exists')
    def test_end_to_end_matching_with_upstream(self, mock_verify_cg, mock_verify_upstream, tmp_path):
        """Test end-to-end: upstream discovery + Chainguard matching."""
        from utils.image_matcher import ImageMatcher

        # Mock DFC mappings
        dfc_yaml = """
images:
  python*: python
  nginx: nginx-fips:latest
"""
        dfc_file = tmp_path / "dfc.yaml"
        dfc_file.write_text(dfc_yaml)

        # Create upstream finder
        upstream_finder = UpstreamImageFinder(
            manual_mappings_file=tmp_path / "nonexistent.yaml",
            min_confidence=0.7,
        )

        # Mock upstream verification to succeed
        mock_verify_upstream.return_value = True

        # Mock Chainguard verification to succeed
        mock_verify_cg.return_value = True

        # Create matcher with upstream finder
        matcher = ImageMatcher(
            cache_dir=tmp_path,
            dfc_mappings_file=dfc_file,
            upstream_finder=upstream_finder,
        )

        # Test: Private image → Upstream → Chainguard
        result = matcher.match("mycompany.io/python:3.12")

        # Should find upstream (python:3.12) and match to Chainguard
        assert result.upstream_image == "python:3.12"
        assert result.upstream_confidence == 0.90
        assert result.upstream_method == "registry_strip"
        assert result.chainguard_image == "cgr.dev/chainguard-private/python:latest"
        assert result.confidence == 0.95
        assert result.method == "dfc"
