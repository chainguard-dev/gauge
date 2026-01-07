"""Tests for GitHub issue search integration."""

import pytest
from unittest.mock import patch, MagicMock
import requests

from integrations.github_issue_search import (
    get_github_token_from_gh_cli,
    GitHubIssue,
    GitHubIssueSearchClient,
)


class TestGitHubIssue:
    """Tests for GitHubIssue dataclass."""

    def test_create_issue(self):
        """Test creating a GitHubIssue instance."""
        issue = GitHubIssue(
            number=123,
            title="Request: Add nginx image",
            body="Please add a Chainguard nginx image",
            url="https://github.com/chainguard-dev/image-requests/issues/123",
            labels=["enhancement", "image-request"],
            state="open",
            created_at="2024-01-15T10:00:00Z",
        )

        assert issue.number == 123
        assert issue.title == "Request: Add nginx image"
        assert issue.body == "Please add a Chainguard nginx image"
        assert "enhancement" in issue.labels
        assert issue.state == "open"


class TestGitHubIssueSearchClientAuth:
    """Tests for GitHubIssueSearchClient authentication."""

    def test_explicit_token_takes_priority(self):
        """Test that explicitly provided token takes priority."""
        client = GitHubIssueSearchClient(github_token="explicit_token")

        assert client.token == "explicit_token"
        assert "Authorization" in client.headers
        assert client.headers["Authorization"] == "token explicit_token"

    @patch.dict("os.environ", {"GITHUB_TOKEN": "env_token"})
    @patch("integrations.github_issue_search.get_github_token_from_gh_cli")
    def test_env_var_token_second_priority(self, mock_gh_cli):
        """Test that env var token is used if no explicit token."""
        mock_gh_cli.return_value = "cli_token"

        client = GitHubIssueSearchClient()

        assert client.token == "env_token"

    @patch.dict("os.environ", {}, clear=True)
    @patch("integrations.github_issue_search.get_github_token_from_gh_cli")
    def test_no_token_raises_error(self, mock_gh_cli):
        """Test that ValueError is raised when no token is available."""
        mock_gh_cli.return_value = None

        import os
        if "GITHUB_TOKEN" in os.environ:
            del os.environ["GITHUB_TOKEN"]

        with pytest.raises(ValueError) as exc_info:
            GitHubIssueSearchClient()

        assert "GitHub authentication required" in str(exc_info.value)
        assert "gh auth login" in str(exc_info.value)

    def test_headers_correctly_set(self):
        """Test that headers are correctly set with token."""
        client = GitHubIssueSearchClient(github_token="test_token")

        assert client.headers["Accept"] == "application/vnd.github.v3+json"
        assert client.headers["Authorization"] == "token test_token"


class TestGitHubIssueSearchClientFetch:
    """Tests for GitHubIssueSearchClient.get_open_issues method."""

    @patch("requests.get")
    def test_get_open_issues_success(self, mock_get):
        """Test successful fetching of open issues."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "number": 1,
                "title": "Request: Add envoy image",
                "body": "Please add envoy proxy",
                "html_url": "https://github.com/chainguard-dev/image-requests/issues/1",
                "labels": [{"name": "enhancement"}],
                "state": "open",
                "created_at": "2024-01-10T10:00:00Z",
            },
            {
                "number": 2,
                "title": "Request: Add redis image",
                "body": "Need redis for caching",
                "html_url": "https://github.com/chainguard-dev/image-requests/issues/2",
                "labels": [],
                "state": "open",
                "created_at": "2024-01-11T10:00:00Z",
            },
        ]
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        client = GitHubIssueSearchClient(github_token="test_token")
        issues = client.get_open_issues(max_pages=1)

        assert len(issues) == 2
        assert issues[0].number == 1
        assert issues[0].title == "Request: Add envoy image"
        assert issues[1].number == 2

    @patch("requests.get")
    def test_get_open_issues_skips_pull_requests(self, mock_get):
        """Test that pull requests are skipped when fetching issues."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "number": 1,
                "title": "Request: Add nginx",
                "body": "Issue body",
                "html_url": "https://github.com/chainguard-dev/image-requests/issues/1",
                "labels": [],
                "state": "open",
                "created_at": "2024-01-10T10:00:00Z",
            },
            {
                "number": 2,
                "title": "Fix typo in README",
                "body": "PR body",
                "html_url": "https://github.com/chainguard-dev/image-requests/pull/2",
                "labels": [],
                "state": "open",
                "created_at": "2024-01-10T10:00:00Z",
                "pull_request": {"url": "..."},  # This marks it as a PR
            },
        ]
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        client = GitHubIssueSearchClient(github_token="test_token")
        issues = client.get_open_issues(max_pages=1)

        assert len(issues) == 1
        assert issues[0].number == 1

    @patch("requests.get")
    def test_get_open_issues_handles_empty_body(self, mock_get):
        """Test handling of issues with null/empty body."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "number": 1,
                "title": "Request with no body",
                "body": None,
                "html_url": "https://github.com/chainguard-dev/image-requests/issues/1",
                "labels": [],
                "state": "open",
                "created_at": "2024-01-10T10:00:00Z",
            },
        ]
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        client = GitHubIssueSearchClient(github_token="test_token")
        issues = client.get_open_issues(max_pages=1)

        assert len(issues) == 1
        assert issues[0].body == ""

    @patch("requests.get")
    def test_get_open_issues_rate_limit_error(self, mock_get):
        """Test handling of rate limit errors."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": "1234567890",
        }
        mock_get.return_value = mock_response
        mock_response.raise_for_status.side_effect = requests.HTTPError(response=mock_response)

        client = GitHubIssueSearchClient(github_token="test_token")

        with pytest.raises(ValueError) as exc_info:
            client.get_open_issues()

        assert "rate limit" in str(exc_info.value).lower()

    @patch("requests.get")
    def test_get_open_issues_404_error(self, mock_get):
        """Test handling of 404 errors (repo not found)."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        mock_response.raise_for_status.side_effect = requests.HTTPError(response=mock_response)

        client = GitHubIssueSearchClient(github_token="test_token")

        with pytest.raises(ValueError) as exc_info:
            client.get_open_issues()

        assert "not found" in str(exc_info.value).lower()

    @patch("requests.get")
    def test_get_open_issues_timeout(self, mock_get):
        """Test handling of timeout errors."""
        mock_get.side_effect = requests.Timeout()

        client = GitHubIssueSearchClient(github_token="test_token")

        with pytest.raises(ValueError) as exc_info:
            client.get_open_issues()

        assert "timed out" in str(exc_info.value).lower()

    @patch("requests.get")
    def test_get_open_issues_pagination(self, mock_get):
        """Test pagination handling for multiple pages."""
        # First page with full results
        page1_response = MagicMock()
        page1_response.status_code = 200
        page1_response.json.return_value = [
            {"number": i, "title": f"Issue {i}", "body": "", "html_url": f"url/{i}",
             "labels": [], "state": "open", "created_at": "2024-01-10T10:00:00Z"}
            for i in range(1, 101)  # 100 issues
        ]
        page1_response.raise_for_status = MagicMock()

        # Second page with partial results (last page)
        page2_response = MagicMock()
        page2_response.status_code = 200
        page2_response.json.return_value = [
            {"number": 101, "title": "Issue 101", "body": "", "html_url": "url/101",
             "labels": [], "state": "open", "created_at": "2024-01-10T10:00:00Z"}
        ]
        page2_response.raise_for_status = MagicMock()

        mock_get.side_effect = [page1_response, page2_response]

        client = GitHubIssueSearchClient(github_token="test_token")
        issues = client.get_open_issues(max_pages=3)

        assert len(issues) == 101
        assert mock_get.call_count == 2  # Stopped after partial page


class TestGitHubIssueSearchClientSearch:
    """Tests for GitHubIssueSearchClient.search_issues method."""

    @patch("requests.get")
    def test_search_issues_success(self, mock_get):
        """Test successful issue search."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "items": [
                {
                    "number": 42,
                    "title": "Request: Add nginx image",
                    "body": "We need nginx for our infrastructure",
                    "html_url": "https://github.com/chainguard-dev/image-requests/issues/42",
                    "labels": [{"name": "enhancement"}],
                    "state": "open",
                    "created_at": "2024-01-15T10:00:00Z",
                },
            ],
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        client = GitHubIssueSearchClient(github_token="test_token")
        issues = client.search_issues("nginx")

        assert len(issues) == 1
        assert issues[0].number == 42
        assert "nginx" in issues[0].title.lower()

    @patch("requests.get")
    def test_search_issues_empty_results(self, mock_get):
        """Test search with no results."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"items": []}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        client = GitHubIssueSearchClient(github_token="test_token")
        issues = client.search_issues("nonexistent-image-xyz")

        assert len(issues) == 0
