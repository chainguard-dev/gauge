"""
LLM-powered issue matching for finding existing image requests.

Matches unmatched container images to GitHub issues in the image-requests
repository using Claude API.
"""

import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, Optional

import anthropic

from constants import DEFAULT_ISSUE_MATCH_CONFIDENCE, DEFAULT_LLM_MODEL
from integrations.github_issue_search import GitHubIssue

logger = logging.getLogger(__name__)


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

    @contextmanager
    def _db_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for SQLite database connections."""
        conn = sqlite3.connect(self.cache_db)
        try:
            yield conn
        finally:
            conn.close()

    def _init_cache_db(self) -> None:
        """Initialize SQLite cache database with issue_match_cache table."""
        with self._db_connection() as conn:
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
        with self._db_connection() as conn:
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
        with self._db_connection() as conn:
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

    def _parse_json_response(self, response_text: str) -> str:
        """Parse JSON from LLM response, handling markdown code blocks."""
        response_text = response_text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        return response_text.strip()

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
            response_text = self._parse_json_response(message.content[0].text)
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
