"""Tests for GitHub API error handling."""

import pytest
from unittest.mock import patch, MagicMock
import requests

from integrations.github_metadata import GitHubMetadataClient
from core.models import ImageTier


class TestGitHubAPIErrors:
    """Tests for GitHub API error responses."""

    @patch("requests.get")
    def test_403_forbidden_error_message(self, mock_get, tmp_path):
        """Test that 403 errors provide helpful message about repository access."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.raise_for_status.side_effect = requests.HTTPError(response=mock_response)
        mock_get.return_value = mock_response

        client = GitHubMetadataClient(github_token="test_token", cache_dir=tmp_path)

        with pytest.raises(ValueError) as exc_info:
            client.get_image_tier("nginx")

        error_msg = str(exc_info.value)
        assert "403" in error_msg or "forbidden" in error_msg.lower()
        assert "chainguard-images/images-private" in error_msg.lower()

    @patch("requests.get")
    def test_404_not_found_error_message(self, mock_get, tmp_path):
        """Test that 404 errors indicate image doesn't exist."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.HTTPError(response=mock_response)
        mock_get.return_value = mock_response

        client = GitHubMetadataClient(github_token="test_token", cache_dir=tmp_path)

        with pytest.raises(ValueError) as exc_info:
            client.get_image_tier("nonexistent-image")

        error_msg = str(exc_info.value)
        assert "not found" in error_msg.lower()
        assert "nonexistent-image" in error_msg

    @patch("requests.get")
    def test_network_error(self, mock_get, tmp_path):
        """Test handling of network errors."""
        mock_get.side_effect = requests.RequestException("Network error")

        client = GitHubMetadataClient(github_token="test_token", cache_dir=tmp_path)

        with pytest.raises(ValueError) as exc_info:
            client.get_image_tier("nginx")

        error_msg = str(exc_info.value)
        assert "failed to fetch metadata" in error_msg.lower()

    @patch("requests.get")
    def test_invalid_yaml_response(self, mock_get, tmp_path):
        """Test handling of invalid YAML in response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "{ invalid yaml: [ unclosed"
        mock_get.return_value = mock_response

        client = GitHubMetadataClient(github_token="test_token", cache_dir=tmp_path)

        with pytest.raises(ValueError) as exc_info:
            client.get_image_tier("nginx")

        error_msg = str(exc_info.value)
        assert "failed to parse" in error_msg.lower() or "yaml" in error_msg.lower()

    @patch("requests.get")
    def test_missing_tier_field(self, mock_get, tmp_path):
        """Test handling when tier field is missing from metadata."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "name: nginx\nversion: 1.0"  # No tier field
        mock_get.return_value = mock_response

        client = GitHubMetadataClient(github_token="test_token", cache_dir=tmp_path)

        with pytest.raises(ValueError) as exc_info:
            client.get_image_tier("nginx")

        error_msg = str(exc_info.value)
        assert "no 'tier' field" in error_msg.lower()

    @patch("requests.get")
    def test_invalid_tier_value(self, mock_get, tmp_path):
        """Test handling of unknown tier value."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "tier: unknown_tier_type"
        mock_get.return_value = mock_response

        client = GitHubMetadataClient(github_token="test_token", cache_dir=tmp_path)

        with pytest.raises(ValueError) as exc_info:
            client.get_image_tier("nginx")

        error_msg = str(exc_info.value)
        assert "unknown tier value" in error_msg.lower()
        assert "unknown_tier_type" in error_msg


class TestGitHubAuthValidation:
    """Tests for authentication validation."""

    def test_token_validation_helper(self):
        """Test that we can check if token has proper access."""
        # This would be a helper function to test GitHub access
        # Could make a simple API call to verify access before running scans
        pass

    @patch("requests.get")
    def test_early_auth_check(self, mock_get, tmp_path):
        """Test early authentication check before scanning."""
        # Simulate the early check we do in CLI
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.raise_for_status.side_effect = requests.HTTPError(response=mock_response)
        mock_get.return_value = mock_response

        client = GitHubMetadataClient(github_token="test_token", cache_dir=tmp_path)

        # Early check should detect 403 and fail fast
        with pytest.raises(ValueError) as exc_info:
            client.get_image_tier("test-image")

        assert "forbidden" in str(exc_info.value).lower()
