"""
GitHub issue search integration for finding existing image requests.

Searches the chainguard-dev/image-requests repository for issues that may
match unmatched images.
"""

import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Optional

import requests

from constants import GITHUB_ISSUE_SEARCH_TIMEOUT

logger = logging.getLogger(__name__)

# GitHub configuration
GITHUB_API_BASE = "https://api.github.com"
IMAGE_REQUESTS_REPO = "chainguard-dev/image-requests"


def get_github_token_from_gh_cli() -> Optional[str]:
    """
    Attempt to get GitHub token from gh CLI.

    Returns:
        GitHub token if gh CLI is installed and authenticated, None otherwise
    """
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            token = result.stdout.strip()
            if token:
                logger.debug("Using GitHub token from gh CLI")
                return token
    except FileNotFoundError:
        logger.debug("gh CLI not found")
    except subprocess.TimeoutExpired:
        logger.debug("gh CLI token fetch timed out")
    except Exception as e:
        logger.debug(f"Failed to get token from gh CLI: {e}")

    return None


@dataclass
class GitHubIssue:
    """Represents a GitHub issue from the image-requests repository."""

    number: int
    """Issue number"""

    title: str
    """Issue title"""

    body: str
    """Issue body/description"""

    url: str
    """URL to the issue on GitHub"""

    labels: list[str]
    """List of label names on the issue"""

    state: str
    """Issue state (open, closed)"""

    created_at: str
    """ISO timestamp of when the issue was created"""


class GitHubIssueSearchClient:
    """
    Client for fetching issues from the chainguard-dev/image-requests repository.

    Requires GitHub authentication for rate limit reasons.
    """

    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize GitHub issue search client.

        Args:
            github_token: Optional GitHub token for API access.
                         Falls back to GITHUB_TOKEN env var, then gh CLI.

        Raises:
            ValueError: If no GitHub token is available (authentication required)
        """
        # Try explicit token, then env var, then gh CLI
        self.token = github_token or os.getenv("GITHUB_TOKEN") or get_github_token_from_gh_cli()

        if not self.token:
            raise ValueError(
                "GitHub authentication required for issue search.\n"
                "To authenticate, either:\n"
                "  1. Run 'gh auth login' (recommended)\n"
                "  2. Set GITHUB_TOKEN environment variable\n"
                "  3. Pass --github-token flag"
            )

        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {self.token}",
        }

    def get_issues(
        self, max_pages: int = 5, per_page: int = 100, state: str = "all"
    ) -> list[GitHubIssue]:
        """
        Fetch issues from the image-requests repository.

        Args:
            max_pages: Maximum number of pages to fetch (default: 5, i.e., 500 issues)
            per_page: Number of issues per page (default: 100, max allowed by GitHub)
            state: Issue state filter - "open", "closed", or "all" (default: "all")

        Returns:
            List of GitHubIssue objects

        Raises:
            ValueError: If API request fails
        """
        all_issues: list[GitHubIssue] = []
        url = f"{GITHUB_API_BASE}/repos/{IMAGE_REQUESTS_REPO}/issues"

        for page in range(1, max_pages + 1):
            params = {
                "state": state,
                "per_page": per_page,
                "page": page,
            }

            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    params=params,
                    timeout=GITHUB_ISSUE_SEARCH_TIMEOUT,
                )
                response.raise_for_status()

                issues_data = response.json()

                if not issues_data:
                    # No more issues
                    break

                for issue_data in issues_data:
                    # Skip pull requests (they appear in issues API too)
                    if "pull_request" in issue_data:
                        continue

                    issue = GitHubIssue(
                        number=issue_data["number"],
                        title=issue_data.get("title", ""),
                        body=issue_data.get("body", "") or "",
                        url=issue_data.get("html_url", ""),
                        labels=[label.get("name", "") for label in issue_data.get("labels", [])],
                        state=issue_data.get("state", "open"),
                        created_at=issue_data.get("created_at", ""),
                    )
                    all_issues.append(issue)

                logger.debug(f"Fetched page {page}: {len(issues_data)} items")

                # Check if we got fewer than requested, meaning last page
                if len(issues_data) < per_page:
                    break

            except requests.HTTPError as e:
                if e.response.status_code == 403:
                    # Check if rate limited
                    remaining = e.response.headers.get("X-RateLimit-Remaining", "unknown")
                    reset_time = e.response.headers.get("X-RateLimit-Reset", "unknown")
                    raise ValueError(
                        f"GitHub API rate limit exceeded or access forbidden.\n"
                        f"Rate limit remaining: {remaining}, resets at: {reset_time}"
                    )
                elif e.response.status_code == 404:
                    raise ValueError(
                        f"Repository {IMAGE_REQUESTS_REPO} not found or not accessible."
                    )
                else:
                    raise ValueError(f"GitHub API error: {e}")

            except requests.Timeout:
                raise ValueError(
                    f"GitHub API request timed out after {GITHUB_ISSUE_SEARCH_TIMEOUT}s"
                )

            except requests.RequestException as e:
                raise ValueError(f"Failed to fetch issues from GitHub: {e}")

        state_desc = "all" if state == "all" else state
        logger.info(f"Loaded {len(all_issues)} {state_desc} issues from {IMAGE_REQUESTS_REPO}")
        return all_issues

    def search_issues(
        self, query: str, max_results: int = 30, state: str = "all"
    ) -> list[GitHubIssue]:
        """
        Search issues using GitHub search API.

        Args:
            query: Search query string
            max_results: Maximum number of results to return
            state: Issue state filter - "open", "closed", or "all" (default: "all")

        Returns:
            List of matching GitHubIssue objects

        Raises:
            ValueError: If API request fails
        """
        url = f"{GITHUB_API_BASE}/search/issues"
        state_filter = f"is:{state}" if state in ("open", "closed") else ""
        params = {
            "q": f"repo:{IMAGE_REQUESTS_REPO} is:issue {state_filter} {query}".strip(),
            "per_page": min(max_results, 100),
        }

        try:
            response = requests.get(
                url,
                headers=self.headers,
                params=params,
                timeout=GITHUB_ISSUE_SEARCH_TIMEOUT,
            )
            response.raise_for_status()

            data = response.json()
            issues: list[GitHubIssue] = []

            for item in data.get("items", [])[:max_results]:
                issue = GitHubIssue(
                    number=item["number"],
                    title=item.get("title", ""),
                    body=item.get("body", "") or "",
                    url=item.get("html_url", ""),
                    labels=[label.get("name", "") for label in item.get("labels", [])],
                    state=item.get("state", "open"),
                    created_at=item.get("created_at", ""),
                )
                issues.append(issue)

            return issues

        except requests.HTTPError as e:
            if e.response.status_code == 403:
                remaining = e.response.headers.get("X-RateLimit-Remaining", "unknown")
                raise ValueError(
                    f"GitHub search API rate limit exceeded.\n"
                    f"Rate limit remaining: {remaining}"
                )
            raise ValueError(f"GitHub search API error: {e}")

        except requests.RequestException as e:
            raise ValueError(f"Failed to search GitHub issues: {e}")
