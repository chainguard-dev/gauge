"""
Common constants and classes shared across the Gauge application.
"""

import argparse
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from utils.logging_helpers import log_error_section, log_warning_section

logger = logging.getLogger(__name__)

# Output configuration for all report types
OUTPUT_CONFIGS = {
    "vuln_summary": {
        "description": "Vulnerability Assessment Summary (HTML)",
        "file_suffix": "assessment.html",
    },
    "cost_analysis": {
        "description": "Vulnerability Cost Analysis (XLSX)",
        "file_suffix": "cost_analysis.xlsx",
    },
    "pricing": {
        "description": "Pricing Quote",
        "formats": {
            "html": {
                "file_suffix": "pricing_quote.html",
                "description": "Pricing Quote (HTML)",
            },
            "txt": {
                "file_suffix": "pricing_quote.txt",
                "description": "Pricing Quote (TXT)",
            },
        },
    },
}


class GitHubAuthValidator:
    """
    Validates GitHub authentication for pricing quote generation.
    """

    def __init__(self, pricing_policy_path: Path):
        self.pricing_policy_path = pricing_policy_path

    def validate(self) -> None:
        """Validate GitHub authentication and repository access."""
        self._check_pricing_policy()
        logger.info("Validating GitHub authentication for pricing tier classification...")
        from integrations.github_metadata import GitHubMetadataClient
        test_client = GitHubMetadataClient()
        if not test_client.token:
            self._handle_no_token()
        self._test_repository_access(test_client.token)

    def _check_pricing_policy(self) -> None:
        """Check that pricing policy file exists."""
        if not self.pricing_policy_path.exists():
            log_error_section(
                "Pricing policy file not found.",
                [f"File not found: {self.pricing_policy_path}", "Use --pricing-policy or create one based on example-pricing-policy.yaml."],
                logger=logger
            )
            sys.exit(1)

    def _handle_no_token(self) -> None:
        """Handle case where no GitHub token is found."""
        log_error_section(
            "GitHub authentication required for pricing.",
            ["Set GITHUB_TOKEN environment variable or use 'gh auth login'."],
            logger=logger
        )
        sys.exit(1)

    def _test_repository_access(self, token: str) -> None:
        """Test GitHub repository access."""
        logger.debug("Testing GitHub repository access...")
        try:
            import requests
            test_url = "https://api.github.com/repos/chainguard-images/images-private"
            response = requests.get(test_url, headers={"Authorization": f"token {token}"}, timeout=5)
            response.raise_for_status()
            logger.info("✓ GitHub authentication configured")
        except requests.HTTPError as e:
            if e.response.status_code == 403:
                self._handle_forbidden_error(e, test_url, token)
            elif e.response.status_code == 404:
                logger.warning("Could not verify repository access (404). Proceeding anyway...")
            else:
                logger.error(f"GitHub API error: {e}")
                sys.exit(1)
        except Exception as e:
            logger.warning(f"Could not verify repository access: {e}. Proceeding anyway...")

    def _handle_forbidden_error(self, error: Exception, test_url: str, token: str) -> None:
        """Handle 403 Forbidden errors."""
        is_saml_issue = "SAML" in error.response.text
        if is_saml_issue:
            self._attempt_token_refresh(test_url)
        else:
            log_error_section(
                "Access to chainguard-images/images-private is forbidden.",
                ["Ensure your GitHub account has access to this repository."],
                logger=logger
            )
            sys.exit(1)

    def _attempt_token_refresh(self, test_url: str) -> None:
        """Attempt to refresh GitHub token via gh CLI."""
        log_warning_section("GitHub token needs SAML SSO authorization.", ["Attempting refresh via gh CLI..."], logger=logger)
        try:
            import subprocess
            subprocess.run(["gh", "auth", "refresh", "-s", "repo"], check=True, capture_output=True)
            logger.info("✓ Token refreshed successfully. Retrying access...")
            from integrations.github_metadata import get_github_token_from_gh_cli
            import requests
            new_token = get_github_token_from_gh_cli()
            if new_token:
                requests.get(test_url, headers={"Authorization": f"token {new_token}"}, timeout=5).raise_for_status()
                logger.info("✓ GitHub authentication configured")
            else:
                raise Exception("Failed to get refreshed token.")
        except (FileNotFoundError, subprocess.CalledProcessError, Exception) as e:
            log_error_section("Failed to refresh GitHub token.", [f"Error: {e}", "Try running 'gh auth refresh -s repo' manually."], logger=logger)
            sys.exit(1)


@dataclass
class MatchConfig:
    """Configuration for image matching operations.

    Groups all matching-related settings into a single object to reduce
    parameter count in functions like match_images().
    """

    min_confidence: float = 0.7
    """Minimum confidence threshold for matches (0.0 - 1.0)"""

    dfc_mappings_file: Optional[Path] = None
    """Path to local DFC mappings YAML file"""

    cache_dir: Optional[Path] = None
    """Cache directory for DFC mappings and other data"""

    find_upstream: bool = True
    """Enable upstream image discovery"""

    upstream_confidence: float = 0.7
    """Minimum confidence for upstream matches (0.0 - 1.0)"""

    upstream_mappings_file: Optional[Path] = None
    """Path to manual upstream mappings YAML file"""

    enable_llm_matching: bool = True
    """Enable LLM-powered fuzzy matching (Tier 4)"""

    llm_model: str = "claude-sonnet-4-5"
    """Claude model to use for LLM matching"""

    llm_confidence_threshold: float = 0.7
    """Minimum confidence for LLM matches (0.0 - 1.0)"""

    anthropic_api_key: Optional[str] = None
    """Anthropic API key for LLM matching"""

    generate_dfc_pr: bool = False
    """Generate DFC contribution files for high-confidence LLM matches"""

    disable_mapping_auto_population: bool = False
    """Disable auto-populating manual mappings"""

    github_token: Optional[str] = None
    """GitHub token for issue search"""


def add_matching_arguments(
    parser_or_group: argparse.ArgumentParser | argparse._ArgumentGroup,
) -> None:
    """
    Add common matching-related arguments to a parser or argument group.

    This helper ensures consistency between the main CLI and match subcommand.

    Args:
        parser_or_group: ArgumentParser or argument group to add arguments to
    """
    from constants import (
        DEFAULT_MATCH_CONFIDENCE,
        DEFAULT_UPSTREAM_CONFIDENCE,
        DEFAULT_LLM_CONFIDENCE,
        DEFAULT_LLM_MODEL,
    )

    parser_or_group.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MATCH_CONFIDENCE,
        help="Minimum match confidence threshold (0.0 - 1.0)."
    )
    parser_or_group.add_argument(
        "--dfc-mappings-file",
        type=Path,
        help="Local DFC mappings YAML file."
    )
    parser_or_group.add_argument(
        "--skip-public-repo-search",
        action="store_true",
        help="Skip upstream image discovery."
    )
    parser_or_group.add_argument(
        "--upstream-confidence",
        type=float,
        default=DEFAULT_UPSTREAM_CONFIDENCE,
        help="Upstream discovery confidence threshold (0.0 - 1.0)."
    )
    parser_or_group.add_argument(
        "--upstream-mappings-file",
        type=Path,
        help="Manual upstream mappings YAML file."
    )
    parser_or_group.add_argument(
        "--disable-llm-matching",
        action="store_true",
        help="Disable LLM-powered fuzzy matching (Tier 4)."
    )
    parser_or_group.add_argument(
        "--llm-model",
        type=str,
        default=DEFAULT_LLM_MODEL,
        help="Claude model for LLM matching."
    )
    parser_or_group.add_argument(
        "--llm-confidence-threshold",
        type=float,
        default=DEFAULT_LLM_CONFIDENCE,
        help="LLM match confidence threshold (0.0 - 1.0)."
    )
    parser_or_group.add_argument(
        "--anthropic-api-key",
        type=str,
        help="Anthropic API key for LLM matching."
    )
    parser_or_group.add_argument(
        "--generate-dfc-pr",
        action="store_true",
        help="Generate DFC contribution files for high-confidence LLM matches."
    )
    parser_or_group.add_argument(
        "--disable-mapping-auto-population",
        action="store_true",
        help="Disable auto-populating manual mappings."
    )


def match_config_from_args(args: argparse.Namespace) -> MatchConfig:
    """
    Create a MatchConfig from parsed command-line arguments.

    Args:
        args: Parsed argparse.Namespace with matching arguments

    Returns:
        MatchConfig populated from the arguments
    """
    return MatchConfig(
        min_confidence=getattr(args, "min_confidence", 0.7),
        dfc_mappings_file=getattr(args, "dfc_mappings_file", None),
        cache_dir=getattr(args, "cache_dir", None),
        find_upstream=not getattr(args, "skip_public_repo_search", False),
        upstream_confidence=getattr(args, "upstream_confidence", 0.7),
        upstream_mappings_file=getattr(args, "upstream_mappings_file", None),
        enable_llm_matching=not getattr(args, "disable_llm_matching", False),
        llm_model=getattr(args, "llm_model", "claude-sonnet-4-5"),
        llm_confidence_threshold=getattr(args, "llm_confidence_threshold", 0.7),
        anthropic_api_key=getattr(args, "anthropic_api_key", None),
        generate_dfc_pr=getattr(args, "generate_dfc_pr", False),
        disable_mapping_auto_population=getattr(args, "disable_mapping_auto_population", False),
        github_token=getattr(args, "github_token", None),
    )
