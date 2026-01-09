"""
Tests for LLM-powered issue matching functionality.
"""

import json
import pytest
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from integrations.github_issue_search import GitHubIssue
from utils.issue_matcher import IssueMatcher, IssueMatchResult, _extract_search_terms


@pytest.fixture
def sample_issues():
    """Sample GitHub issues for testing."""
    return [
        GitHubIssue(
            number=123,
            title="Request: Add envoy-proxy image",
            body="Please add a Chainguard image for Envoy proxy. We need it for our service mesh.",
            url="https://github.com/chainguard-dev/image-requests/issues/123",
            labels=["enhancement", "image-request"],
            state="open",
            created_at="2024-01-15T10:00:00Z",
        ),
        GitHubIssue(
            number=456,
            title="Request: Add redis image",
            body="Need redis for caching layer",
            url="https://github.com/chainguard-dev/image-requests/issues/456",
            labels=["enhancement"],
            state="open",
            created_at="2024-01-10T10:00:00Z",
        ),
        GitHubIssue(
            number=789,
            title="Bug: Python image missing pip",
            body="The python image doesn't have pip installed",
            url="https://github.com/chainguard-dev/image-requests/issues/789",
            labels=["bug"],
            state="open",
            created_at="2024-01-05T10:00:00Z",
        ),
    ]


@pytest.fixture
def mock_anthropic_client():
    """Mock Anthropic API client."""
    mock_client = Mock()
    mock_message = Mock()
    mock_content = Mock()
    mock_content.text = json.dumps({
        "issue_number": 123,
        "confidence": 0.85,
        "reasoning": "Issue #123 explicitly requests Envoy proxy image which matches the unmatched image"
    })
    mock_message.content = [mock_content]
    mock_client.messages.create.return_value = mock_message
    return mock_client


@pytest.fixture
def issue_matcher(tmp_path, mock_anthropic_client):
    """Create IssueMatcher with mocked API client."""
    with patch('utils.issue_matcher.anthropic.Anthropic', return_value=mock_anthropic_client):
        matcher = IssueMatcher(
            api_key="test-key",
            model="claude-sonnet-4-5",
            cache_dir=tmp_path,
            confidence_threshold=0.7,
        )
    return matcher


class TestIssueMatcher:
    """Test LLM-powered issue matching."""

    def test_issue_match_success(self, issue_matcher, mock_anthropic_client, sample_issues):
        """Test successful issue matching."""
        result = issue_matcher.match("envoyproxy/envoy:v1.28.0", sample_issues)

        assert result.matched_issue is not None
        assert result.matched_issue.number == 123
        assert result.confidence == 0.85
        assert "envoy" in result.reasoning.lower()
        assert result.cached is False

    def test_issue_match_caching(self, issue_matcher, mock_anthropic_client, sample_issues):
        """Test that issue match results are cached."""
        # First call - not cached
        result1 = issue_matcher.match("envoyproxy/envoy:v1.28.0", sample_issues)
        assert result1.cached is False
        assert mock_anthropic_client.messages.create.call_count == 1

        # Second call - should be cached
        result2 = issue_matcher.match("envoyproxy/envoy:v1.28.0", sample_issues)
        assert result2.cached is True
        assert result2.matched_issue.number == result1.matched_issue.number
        assert result2.confidence == result1.confidence
        # API should not be called again
        assert mock_anthropic_client.messages.create.call_count == 1

    def test_issue_match_no_match(self, tmp_path, sample_issues):
        """Test issue matching when no match is found."""
        mock_client = Mock()
        mock_message = Mock()
        mock_content = Mock()
        mock_content.text = json.dumps({
            "issue_number": None,
            "confidence": 0.0,
            "reasoning": "No existing issue requests this custom internal image"
        })
        mock_message.content = [mock_content]
        mock_client.messages.create.return_value = mock_message

        with patch('utils.issue_matcher.anthropic.Anthropic', return_value=mock_client):
            matcher = IssueMatcher(
                api_key="test-key",
                cache_dir=tmp_path,
            )

            result = matcher.match("internal-registry/custom-app:v1", sample_issues)

            assert result.matched_issue is None
            assert result.confidence == 0.0

    def test_issue_match_below_threshold(self, tmp_path, sample_issues):
        """Test that matches below confidence threshold return no match."""
        mock_client = Mock()
        mock_message = Mock()
        mock_content = Mock()
        mock_content.text = json.dumps({
            "issue_number": 456,
            "confidence": 0.5,  # Below default threshold of 0.7
            "reasoning": "Weak match"
        })
        mock_message.content = [mock_content]
        mock_client.messages.create.return_value = mock_message

        with patch('utils.issue_matcher.anthropic.Anthropic', return_value=mock_client):
            matcher = IssueMatcher(
                api_key="test-key",
                cache_dir=tmp_path,
                confidence_threshold=0.7,
            )

            result = matcher.match("redis:7", sample_issues)

            # Even though LLM suggested issue 456, confidence is below threshold
            assert result.matched_issue is None
            assert result.confidence == 0.5

    def test_issue_match_empty_issues(self, issue_matcher):
        """Test matching with empty issues list."""
        result = issue_matcher.match("nginx:latest", [])

        assert result.matched_issue is None
        assert result.confidence == 0.0
        assert "no open issues" in result.reasoning.lower()

    def test_issue_match_no_api_key(self, tmp_path):
        """Test that matcher handles missing API key gracefully."""
        with patch.dict('os.environ', {}, clear=True):
            import os
            if "ANTHROPIC_API_KEY" in os.environ:
                del os.environ["ANTHROPIC_API_KEY"]

            matcher = IssueMatcher(
                api_key=None,
                cache_dir=tmp_path,
            )

            result = matcher.match("nginx:latest", [
                GitHubIssue(
                    number=1, title="Test", body="Test", url="url",
                    labels=[], state="open", created_at="2024-01-01T00:00:00Z"
                )
            ])

            assert result.matched_issue is None
            assert "disabled" in result.reasoning.lower()

    def test_issue_match_invalid_json(self, tmp_path, sample_issues):
        """Test handling of invalid JSON response from LLM."""
        mock_client = Mock()
        mock_message = Mock()
        mock_content = Mock()
        mock_content.text = "This is not valid JSON"
        mock_message.content = [mock_content]
        mock_client.messages.create.return_value = mock_message

        with patch('utils.issue_matcher.anthropic.Anthropic', return_value=mock_client):
            matcher = IssueMatcher(
                api_key="test-key",
                cache_dir=tmp_path,
            )

            result = matcher.match("nginx:latest", sample_issues)

            assert result.matched_issue is None
            assert "json" in result.reasoning.lower()

    def test_issue_match_suggested_issue_not_found(self, tmp_path, sample_issues):
        """Test handling when LLM suggests an issue number not in the list."""
        mock_client = Mock()
        mock_message = Mock()
        mock_content = Mock()
        mock_content.text = json.dumps({
            "issue_number": 9999,  # This issue doesn't exist in sample_issues
            "confidence": 0.9,
            "reasoning": "High confidence match"
        })
        mock_message.content = [mock_content]
        mock_client.messages.create.return_value = mock_message

        with patch('utils.issue_matcher.anthropic.Anthropic', return_value=mock_client):
            matcher = IssueMatcher(
                api_key="test-key",
                cache_dir=tmp_path,
            )

            result = matcher.match("nginx:latest", sample_issues)

            # Should return no match since issue 9999 doesn't exist
            assert result.matched_issue is None
            assert result.confidence == 0.0

    def test_issue_match_handles_markdown_json(self, tmp_path, sample_issues):
        """Test that matcher handles JSON wrapped in markdown code blocks."""
        mock_client = Mock()
        mock_message = Mock()
        mock_content = Mock()
        # LLM sometimes wraps JSON in markdown
        mock_content.text = """```json
{
    "issue_number": 456,
    "confidence": 0.8,
    "reasoning": "Redis match"
}
```"""
        mock_message.content = [mock_content]
        mock_client.messages.create.return_value = mock_message

        with patch('utils.issue_matcher.anthropic.Anthropic', return_value=mock_client):
            matcher = IssueMatcher(
                api_key="test-key",
                cache_dir=tmp_path,
            )

            result = matcher.match("redis:7", sample_issues)

            assert result.matched_issue is not None
            assert result.matched_issue.number == 456


class TestIssueMatcherCache:
    """Test issue matcher cache functionality."""

    def test_separate_cache_table(self, tmp_path):
        """Test that issue matcher uses a separate cache table from llm_cache."""
        with patch('utils.issue_matcher.anthropic.Anthropic', return_value=Mock()):
            matcher = IssueMatcher(
                api_key="test-key",
                cache_dir=tmp_path,
            )

        # Check that the issue_match_cache table exists
        conn = sqlite3.connect(tmp_path / "llm_cache.db")
        cursor = conn.cursor()

        # Query sqlite_master to check table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        assert "issue_match_cache" in tables
        conn.close()

    def test_cache_persistence(self, tmp_path, sample_issues):
        """Test that cache persists across matcher instances."""
        mock_client = Mock()
        mock_message = Mock()
        mock_content = Mock()
        mock_content.text = json.dumps({
            "issue_number": 123,
            "confidence": 0.85,
            "reasoning": "Test match"
        })
        mock_message.content = [mock_content]
        mock_client.messages.create.return_value = mock_message

        # First instance - makes API call
        with patch('utils.issue_matcher.anthropic.Anthropic', return_value=mock_client):
            matcher1 = IssueMatcher(api_key="test-key", cache_dir=tmp_path)
            result1 = matcher1.match("envoy:v1", sample_issues)
            assert result1.cached is False
            assert mock_client.messages.create.call_count == 1

        # Second instance - should use cache
        mock_client2 = Mock()
        with patch('utils.issue_matcher.anthropic.Anthropic', return_value=mock_client2):
            matcher2 = IssueMatcher(api_key="test-key", cache_dir=tmp_path)
            result2 = matcher2.match("envoy:v1", sample_issues)
            assert result2.cached is True
            # New client should not be called since result is cached
            assert mock_client2.messages.create.call_count == 0


class TestIssueMatchResult:
    """Test IssueMatchResult dataclass."""

    def test_create_result_with_match(self, sample_issues):
        """Test creating result with a match."""
        result = IssueMatchResult(
            image_name="envoy:v1",
            matched_issue=sample_issues[0],
            confidence=0.9,
            reasoning="Direct match",
        )

        assert result.image_name == "envoy:v1"
        assert result.matched_issue.number == 123
        assert result.confidence == 0.9
        assert result.cached is False
        assert result.latency_ms == 0.0

    def test_create_result_without_match(self):
        """Test creating result without a match."""
        result = IssueMatchResult(
            image_name="custom:v1",
            matched_issue=None,
            confidence=0.0,
            reasoning="No match found",
        )

        assert result.matched_issue is None
        assert result.confidence == 0.0


class TestExtractSearchTerms:
    """Test search term extraction from image names."""

    def test_simple_image_name(self):
        """Test extracting terms from simple image name."""
        terms = _extract_search_terms("nginx:latest")
        assert "nginx" in terms

    def test_image_with_org(self):
        """Test extracting terms from org/image format."""
        terms = _extract_search_terms("alpine/jmeter:5")
        assert "jmeter" in terms

    def test_image_with_registry(self):
        """Test extracting terms from registry/org/image format."""
        terms = _extract_search_terms("docker.io/library/nginx:1.25")
        assert "nginx" in terms

    def test_image_with_private_registry(self):
        """Test extracting terms from private registry image."""
        terms = _extract_search_terms("gcr.io/myproject/myapp:v1")
        assert "myapp" in terms

    def test_image_with_hyphen(self):
        """Test extracting terms from hyphenated image name."""
        terms = _extract_search_terms("kube-state-metrics:v2.0")
        assert "kube-state-metrics" in terms
        assert "kube" in terms
        assert "state" in terms
        assert "metrics" in terms

    def test_image_with_underscore(self):
        """Test extracting terms from underscore-separated image name."""
        terms = _extract_search_terms("fluent_bit:latest")
        assert "fluent_bit" in terms
        assert "fluent" in terms
        assert "bit" in terms

    def test_image_with_digest(self):
        """Test extracting terms from image with digest."""
        terms = _extract_search_terms("nginx@sha256:abc123")
        assert "nginx" in terms

    def test_short_components_filtered(self):
        """Test that very short components are filtered out."""
        terms = _extract_search_terms("go-app:v1")
        assert "go-app" in terms
        assert "app" in terms
        # "go" should be filtered out as it's only 2 chars
        assert "go" not in terms

    def test_ghcr_registry(self):
        """Test extracting terms from ghcr.io image."""
        terms = _extract_search_terms("ghcr.io/external-secrets/external-secrets:v0.9.0")
        assert "external-secrets" in terms
        assert "external" in terms
        assert "secrets" in terms
