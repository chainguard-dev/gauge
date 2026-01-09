"""
LLM-powered issue matching for finding existing image requests.

Matches unmatched container images to GitHub issues in the image-requests
repository using Claude API.
"""

import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import anthropic

from constants import DEFAULT_ISSUE_MATCH_CONFIDENCE, DEFAULT_LLM_MODEL
from integrations.github_issue_search import GitHubIssue, GitHubIssueSearchClient
from utils.llm_utils import db_connection, parse_json_response

logger = logging.getLogger(__name__)


def _extract_search_terms(image_name: str) -> list[str]:
    """
    Extract search terms from an image name for GitHub issue search.

    Args:
        image_name: Full image name (e.g., "alpine/jmeter:5", "docker.io/nginx:latest")

    Returns:
        List of search terms to use
    """
    # Remove registry prefix if present
    name = image_name
    if "/" in name:
        # Handle registry/org/image or org/image patterns
        parts = name.split("/")
        # If first part looks like a registry (has dots or is known registry), skip it
        if "." in parts[0] or parts[0] in ("docker", "library"):
            parts = parts[1:]
        name = parts[-1] if parts else name

    # Remove tag
    if ":" in name:
        name = name.split(":")[0]

    # Remove digest
    if "@" in name:
        name = name.split("@")[0]

    # Split on common separators to get component terms
    terms = []
    # Add the full name first
    if name:
        terms.append(name)

    # Also add individual components if name has separators
    for sep in ["-", "_"]:
        if sep in name:
            for part in name.split(sep):
                if part and len(part) > 2 and part not in terms:
                    terms.append(part)

    return terms


def search_github_issues_for_images(
    unmatched_images: list[str],
    anthropic_api_key: Optional[str] = None,
    llm_model: str = DEFAULT_LLM_MODEL,
    cache_dir: Optional[Path] = None,
    confidence_threshold: float = DEFAULT_ISSUE_MATCH_CONFIDENCE,
    github_token: Optional[str] = None,
) -> tuple[list[tuple[str, "IssueMatchResult"]], list[str]]:
    """
    Search GitHub issues for unmatched images.

    This is a convenience function that initializes the GitHub client and
    IssueMatcher, then searches for all unmatched images.

    Uses a hybrid approach:
    1. Fetches recent open issues for general context
    2. For each image, searches GitHub for issues mentioning the image name
    3. Combines results and uses LLM to find the best match

    Args:
        unmatched_images: List of image names to search for
        anthropic_api_key: Anthropic API key for LLM matching
        llm_model: Claude model to use
        cache_dir: Cache directory for results
        confidence_threshold: Minimum confidence for matches
        github_token: GitHub token for API access

    Returns:
        Tuple of (issue_matches, no_issue_matches) where:
        - issue_matches: List of (image, IssueMatchResult) for images with matching issues
        - no_issue_matches: List of image names with no matching issues

    Raises:
        ValueError: If GitHub authentication fails
    """
    github_client = GitHubIssueSearchClient(github_token=github_token)
    issue_matcher = IssueMatcher(
        api_key=anthropic_api_key,
        model=llm_model,
        cache_dir=cache_dir,
        confidence_threshold=confidence_threshold,
    )

    # Fetch recent open issues as baseline context (reduced from 500 to 200)
    recent_issues = github_client.get_open_issues(max_pages=2)
    recent_issue_numbers = {issue.number for issue in recent_issues}
    logger.info(f"Loaded {len(recent_issues)} recent open issues as baseline")

    issue_matches = []
    no_issue_matches = []

    for image in unmatched_images:
        # Search for issues specifically mentioning this image
        search_terms = _extract_search_terms(image)
        search_issues = []

        for term in search_terms[:2]:  # Limit to first 2 terms to avoid too many API calls
            try:
                found = github_client.search_issues(term, max_results=20)
                for issue in found:
                    if issue.number not in recent_issue_numbers:
                        search_issues.append(issue)
                        recent_issue_numbers.add(issue.number)
            except ValueError as e:
                logger.debug(f"Search for '{term}' failed: {e}")

        # Combine recent issues with search results
        combined_issues = recent_issues + search_issues
        if search_issues:
            logger.debug(f"Found {len(search_issues)} additional issues for '{image}' via search")

        result = issue_matcher.match(image, combined_issues)
        if result.matched_issue:
            issue_matches.append((image, result))
        else:
            no_issue_matches.append(image)

    return issue_matches, no_issue_matches


def log_issue_search_results(
    issue_matches: list[tuple[str, "IssueMatchResult"]],
    no_issue_matches: list[str],
) -> None:
    """
    Log GitHub issue search results.

    Args:
        issue_matches: List of (image, IssueMatchResult) for images with matching issues
        no_issue_matches: List of image names with no matching issues
    """
    if issue_matches:
        logger.info("\n" + "=" * 80)
        logger.info("Existing GitHub Issues Found for Unmatched Images:")
        logger.info("=" * 80)
        for image, result in issue_matches:
            logger.info(f"  {image}")
            logger.info(f"    Issue: {result.matched_issue.title}")
            logger.info(f"    URL: {result.matched_issue.url}")
            logger.info(f"    Confidence: {result.confidence:.0%}")
        logger.info("=" * 80)

    if no_issue_matches:
        images_list = "\n".join(f"  - {image}" for image in no_issue_matches)
        logger.info(f"\nNo matching GitHub issues found for {len(no_issue_matches)} images:\n{images_list}")


@dataclass
class IssueMatchResult:
    """Result of matching an image to a GitHub issue."""

    image_name: str
    """The unmatched image that was searched"""

    matched_issue: Optional[GitHubIssue]
    """The matched GitHub issue, or None if no match found"""

    confidence: float
    """Confidence score (0.0 - 1.0)"""

    reasoning: str
    """LLM's reasoning for the match"""

    cached: bool = False
    """Whether result was from cache"""

    latency_ms: float = 0.0
    """API call latency in milliseconds"""


class IssueMatcher:
    """
    LLM-powered matcher for finding GitHub issues related to unmatched images.

    Uses Claude to analyze image names and GitHub issue content to find
    potential matches.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_LLM_MODEL,
        cache_dir: Optional[Path] = None,
        confidence_threshold: float = DEFAULT_ISSUE_MATCH_CONFIDENCE,
    ):
        """
        Initialize issue matcher.

        Args:
            api_key: Anthropic API key (falls back to ANTHROPIC_API_KEY env var)
            model: Claude model to use
            cache_dir: Directory for SQLite cache (default: ~/.cache/gauge)
            confidence_threshold: Minimum confidence to consider a match
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self.confidence_threshold = confidence_threshold

        if not self.api_key:
            logger.warning(
                "No Anthropic API key found. Issue matching will be disabled. "
                "To enable, either:\n"
                "  1. Set ANTHROPIC_API_KEY environment variable\n"
                "  2. Pass api_key to constructor\n"
                "  3. Use --anthropic-api-key flag"
            )
            self.client = None
        else:
            self.client = anthropic.Anthropic(api_key=self.api_key)

        # Initialize cache (separate table from llm_cache)
        self.cache_dir = cache_dir or Path.home() / ".cache" / "gauge"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_db = self.cache_dir / "llm_cache.db"
        self._init_cache_db()

        # Telemetry
        self.telemetry_file = self.cache_dir / "issue_match_telemetry.jsonl"

    def _init_cache_db(self) -> None:
        """Initialize SQLite cache database with issue_match_cache table."""
        with db_connection(self.cache_db) as conn:
            cursor = conn.cursor()
            # Separate table from llm_cache to avoid conflicts
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS issue_match_cache (
                    image_name TEXT PRIMARY KEY,
                    model TEXT,
                    issue_number INTEGER,
                    issue_title TEXT,
                    issue_url TEXT,
                    confidence REAL,
                    reasoning TEXT,
                    timestamp INTEGER
                )
            """
            )
            conn.commit()

    def _get_cached_result(
        self, image_name: str, issues: list[GitHubIssue]
    ) -> Optional[IssueMatchResult]:
        """
        Get cached result for image.

        Args:
            image_name: Image name to look up
            issues: Current list of issues (to reconstruct GitHubIssue object)

        Returns:
            Cached result if available and valid, None otherwise
        """
        with db_connection(self.cache_db) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT issue_number, issue_title, issue_url, confidence, reasoning
                FROM issue_match_cache
                WHERE image_name = ? AND model = ?
            """,
                (image_name, self.model),
            )
            row = cursor.fetchone()

        if row:
            issue_number, issue_title, issue_url, confidence, reasoning = row

            # Reconstruct GitHubIssue if we have a match
            matched_issue = None
            if issue_number:
                # Try to find the full issue in current issues
                for issue in issues:
                    if issue.number == issue_number:
                        matched_issue = issue
                        break

                # If issue not found in current list but was cached, create minimal issue
                if not matched_issue:
                    matched_issue = GitHubIssue(
                        number=issue_number,
                        title=issue_title or "",
                        body="",
                        url=issue_url or "",
                        labels=[],
                        state="open",
                        created_at="",
                    )

            logger.debug(f"Cache hit for issue match: {image_name}")
            return IssueMatchResult(
                image_name=image_name,
                matched_issue=matched_issue,
                confidence=confidence,
                reasoning=reasoning,
                cached=True,
            )

        return None

    def _cache_result(self, result: IssueMatchResult) -> None:
        """
        Cache issue match result.

        Args:
            result: Match result to cache
        """
        with db_connection(self.cache_db) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO issue_match_cache
                (image_name, model, issue_number, issue_title, issue_url, confidence, reasoning, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    result.image_name,
                    self.model,
                    result.matched_issue.number if result.matched_issue else None,
                    result.matched_issue.title if result.matched_issue else None,
                    result.matched_issue.url if result.matched_issue else None,
                    result.confidence,
                    result.reasoning,
                    int(time.time()),
                ),
            )
            conn.commit()

    def _log_telemetry(self, result: IssueMatchResult, success: bool) -> None:
        """
        Log telemetry data for issue matching.

        Args:
            result: Match result
            success: Whether a match was found above threshold
        """
        telemetry = {
            "timestamp": int(time.time()),
            "image_name": result.image_name,
            "model": self.model,
            "issue_number": result.matched_issue.number if result.matched_issue else None,
            "issue_title": result.matched_issue.title if result.matched_issue else None,
            "confidence": result.confidence,
            "success": success,
            "cached": result.cached,
            "latency_ms": result.latency_ms,
        }

        with open(self.telemetry_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(telemetry) + "\n")

    def _build_prompt(self, image_name: str, issues: list[GitHubIssue]) -> str:
        """
        Build the matching prompt for Claude.

        Args:
            image_name: Image name to match
            issues: List of GitHub issues to search through

        Returns:
            Formatted prompt string
        """
        # Format issues for the prompt (limit body length to avoid token limits)
        issues_text = []
        for issue in issues[:100]:  # Limit to 100 issues to stay within context
            body_preview = issue.body[:500] if issue.body else "(no description)"
            body_preview = body_preview.replace("\n", " ").strip()
            issues_text.append(
                f"Issue #{issue.number}: {issue.title}\n"
                f"  URL: {issue.url}\n"
                f"  Description: {body_preview}..."
            )

        issues_str = "\n\n".join(issues_text) if issues_text else "(no open issues)"

        prompt = f"""You are an expert at matching container images to GitHub issue requests.

**Task:** Determine if any of the GitHub issues below is requesting the same container image (or a functionally equivalent image) as the one provided.

**Image to match:** {image_name}

**Open GitHub Issues from chainguard-dev/image-requests:**

{issues_str}

**Matching Guidelines:**
1. Look for issues requesting the same software/tool
2. Consider name variations (e.g., "postgres" vs "postgresql", "mongo" vs "mongodb")
3. Consider registry prefixes - ignore them for matching (e.g., "docker.io/nginx" matches "nginx")
4. Consider version tags - ignore them for matching (e.g., "nginx:1.25" matches "nginx:latest")
5. The issue should be requesting a NEW Chainguard image, not reporting bugs about existing ones

**Confidence Scoring:**
- 0.9+: Exact match - issue explicitly requests this exact image
- 0.8-0.89: Strong match - issue requests the same software with minor name variation
- 0.7-0.79: Reasonable match - issue requests functionally equivalent software
- Below 0.7: Return null (no confident match)

**Output Format (JSON):**
{{
  "issue_number": 123,
  "confidence": 0.85,
  "reasoning": "Brief explanation of why this issue matches"
}}

If no issue matches with sufficient confidence:
{{
  "issue_number": null,
  "confidence": 0.0,
  "reasoning": "No matching issue found"
}}

Respond with ONLY the JSON output, no additional text."""

        return prompt

    def match(self, image_name: str, issues: list[GitHubIssue]) -> IssueMatchResult:
        """
        Match an unmatched image to a GitHub issue.

        Args:
            image_name: The unmatched image name
            issues: List of open GitHub issues to search

        Returns:
            IssueMatchResult with match details
        """
        # Check if LLM matching is available
        if not self.client:
            logger.debug("Issue matching disabled (no API key)")
            return IssueMatchResult(
                image_name=image_name,
                matched_issue=None,
                confidence=0.0,
                reasoning="Issue matching disabled (no API key)",
            )

        # Check cache first
        cached_result = self._get_cached_result(image_name, issues)
        if cached_result:
            self._log_telemetry(
                cached_result, cached_result.confidence >= self.confidence_threshold
            )
            return cached_result

        if not issues:
            result = IssueMatchResult(
                image_name=image_name,
                matched_issue=None,
                confidence=0.0,
                reasoning="No open issues to search",
            )
            self._cache_result(result)
            return result

        start_time = time.time()

        try:
            prompt = self._build_prompt(image_name, issues)

            logger.debug(f"LLM issue matching for '{image_name}' (model: {self.model})")
            message = self.client.messages.create(
                model=self.model,
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )

            latency_ms = (time.time() - start_time) * 1000
            response_text = parse_json_response(message.content[0].text)
            response = json.loads(response_text)

            issue_number = response.get("issue_number")
            confidence = response.get("confidence", 0.0)
            reasoning = response.get("reasoning", "")

            # Find the matched issue
            matched_issue = None
            if issue_number and confidence >= self.confidence_threshold:
                for issue in issues:
                    if issue.number == issue_number:
                        matched_issue = issue
                        break

                if not matched_issue:
                    logger.warning(
                        f"LLM suggested issue #{issue_number} which was not found in issues list"
                    )
                    confidence = 0.0
                    reasoning = f"Suggested issue #{issue_number} not found"

            result = IssueMatchResult(
                image_name=image_name,
                matched_issue=matched_issue if confidence >= self.confidence_threshold else None,
                confidence=confidence,
                reasoning=reasoning,
                latency_ms=latency_ms,
            )

            # Cache and log
            self._cache_result(result)
            success = result.matched_issue is not None
            self._log_telemetry(result, success)

            if success:
                logger.info(
                    f"Issue match for {image_name}: #{matched_issue.number} - {matched_issue.title} "
                    f"(confidence: {confidence:.0%})"
                )
            else:
                logger.debug(f"No issue match found for {image_name}")

            return result

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse issue match response: {e}")
            result = IssueMatchResult(
                image_name=image_name,
                matched_issue=None,
                confidence=0.0,
                reasoning=f"JSON parse error: {e}",
                latency_ms=(time.time() - start_time) * 1000,
            )
            self._cache_result(result)
            return result

        except anthropic.APIError as e:
            logger.error(f"Anthropic API error in issue matching: {e}")
            return IssueMatchResult(
                image_name=image_name,
                matched_issue=None,
                confidence=0.0,
                reasoning=f"API error: {e}",
                latency_ms=(time.time() - start_time) * 1000,
            )

        except Exception as e:
            logger.error(f"Issue matching error: {e}")
            return IssueMatchResult(
                image_name=image_name,
                matched_issue=None,
                confidence=0.0,
                reasoning=f"Error: {e}",
                latency_ms=(time.time() - start_time) * 1000,
            )
