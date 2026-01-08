"""
Command-line interface for Gauge - Container Vulnerability Assessment Tool.

Provides a clean, intuitive CLI for vulnerability scanning with two output types:
- HTML: Vulnerability assessment summary reports
- XLSX: Vulnerability cost analysis with ROI calculations
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

# ASCII art logo for Gauge
GAUGE_BANNER = r"""
    ██████╗  █████╗ ██╗   ██╗ ██████╗ ███████╗
   ██╔════╝ ██╔══██╗██║   ██║██╔════╝ ██╔════╝
   ██║  ███╗███████║██║   ██║██║  ███╗█████╗
   ██║   ██║██╔══██║██║   ██║██║   ██║██╔══╝
   ╚██████╔╝██║  ██║╚██████╔╝╚██████╔╝███████╗
    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
"""

from constants import (
    DEFAULT_HOURS_PER_VULNERABILITY,
    DEFAULT_HOURLY_RATE,
    DEFAULT_MAX_WORKERS,
    DEFAULT_PLATFORM,
    DEFAULT_MATCH_CONFIDENCE,
    DEFAULT_UPSTREAM_CONFIDENCE,
    DEFAULT_LLM_CONFIDENCE,
    DEFAULT_LLM_MODEL,
    DEFAULT_CHPS_MAX_WORKERS,
)
from common import OUTPUT_CONFIGS, GitHubAuthValidator
from core.orchestrator import GaugeOrchestrator


def print_banner():
    """Print the Gauge ASCII art banner."""
    print(GAUGE_BANNER)


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%H:%M:%S",
    )

    # Suppress noisy HTTP request logs from httpx/anthropic SDK
    # These just show "HTTP Request: POST ... 200 OK" which isn't useful
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("anthropic").setLevel(logging.WARNING)


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments for the main scan command."""
    parser = argparse.ArgumentParser(
        description="Gauge - Container Vulnerability Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Add argument groups
    io_group = parser.add_argument_group("input/output")
    common_group = parser.add_argument_group("common options")
    html_group = parser.add_argument_group("assessment summary options (HTML)")
    xlsx_group = parser.add_argument_group("cost analysis options (XLSX)")
    cache_group = parser.add_argument_group("cache options")
    matching_group = parser.add_argument_group("matching options")
    features_group = parser.add_argument_group("optional features")
    auth_group = parser.add_argument_group("authentication options")

    # Input/Output arguments
    io_group.add_argument("-i", "--input", type=Path, default=Path("images.csv"), help="Input CSV file.")
    io_group.add_argument("-o", "--output", type=str, default=None, help="Output types (comma-separated).")
    io_group.add_argument("--output-dir", type=Path, default=Path("."), help="Output directory.")
    io_group.add_argument("--pricing-policy", type=Path, default=Path("pricing-policy.yaml"), help="Pricing policy file.")

    # Common options
    common_group.add_argument("-c", "--customer", dest="customer_name", default="Customer", help="Customer name.")
    common_group.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS, help="Number of parallel workers.")
    common_group.add_argument("--platform", default=DEFAULT_PLATFORM, help="Image platform.")

    # HTML-specific options
    html_group.add_argument("-e", "--exec-summary", type=Path, default=Path("exec-summary.md"), help="Executive summary file.")
    html_group.add_argument("-a", "--appendix", type=Path, default=Path("appendix.md"), help="Custom appendix file.")

    # XLSX-specific options
    xlsx_group.add_argument("--hours-per-vuln", type=float, default=DEFAULT_HOURS_PER_VULNERABILITY, help="Hours per vulnerability.")
    xlsx_group.add_argument("--hourly-rate", type=float, default=DEFAULT_HOURLY_RATE, help="Hourly rate in USD.")

    # Cache options
    cache_group.add_argument("--cache-dir", type=Path, default=Path(".cache"), help="Cache directory.")
    cache_group.add_argument("--no-cache", action="store_true", help="Disable caching.")
    cache_group.add_argument("--clear-cache", action="store_true", help="Clear cache.")
    cache_group.add_argument("--no-fresh-check", action="store_true", help="Skip fresh image check.")
    cache_group.add_argument("--resume", action="store_true", help="Resume from checkpoint.")
    cache_group.add_argument("--checkpoint-file", type=Path, default=Path(".gauge_checkpoint.json"), help="Checkpoint file.")

    # Matching options
    matching_group.add_argument("--min-confidence", type=float, default=DEFAULT_MATCH_CONFIDENCE, help="Min match confidence.")
    matching_group.add_argument("--dfc-mappings-file", type=Path, help="Local DFC mappings file.")
    matching_group.add_argument("--skip-public-repo-search", action="store_true", help="Skip upstream discovery.")
    matching_group.add_argument("--upstream-confidence", type=float, default=DEFAULT_UPSTREAM_CONFIDENCE, help="Upstream discovery confidence.")
    matching_group.add_argument("--upstream-mappings-file", type=Path, help="Manual upstream mappings file.")
    matching_group.add_argument("--disable-llm-matching", action="store_true", help="Disable LLM matching.")
    matching_group.add_argument("--llm-model", type=str, default=DEFAULT_LLM_MODEL, help="Claude model for matching.")
    matching_group.add_argument("--llm-confidence-threshold", type=float, default=DEFAULT_LLM_CONFIDENCE, help="LLM match confidence.")
    matching_group.add_argument("--anthropic-api-key", type=str, help="Anthropic API key.")
    matching_group.add_argument("--generate-dfc-pr", action="store_true", help="Generate DFC contribution files.")
    matching_group.add_argument("--disable-mapping-auto-population", action="store_true", help="Disable auto-populating mappings.")

    # Optional features
    features_group.add_argument("--with-chps", action="store_true", help="Include CHPS scoring.")
    features_group.add_argument("--with-fips", action="store_true", help="Include FIPS analysis.")
    features_group.add_argument("--with-kevs", action="store_true", help="Include KEV data.")
    features_group.add_argument("--with-all", action="store_true", help="Enable all optional features.")
    features_group.add_argument("--include-negligible", action="store_true", help="Include Negligible/Unknown CVEs in counts (excluded by default).")
    features_group.add_argument("--chps-max-workers", type=int, default=DEFAULT_CHPS_MAX_WORKERS, help="Number of parallel CHPS scanning threads.")

    # Authentication options
    auth_group.add_argument("--gcr-credentials", type=Path, help="Path to Google Cloud service account JSON for gcr.io authentication.")
    auth_group.add_argument("--no-gcr-auth", action="store_true", help="Disable automatic GCR authentication.")

    # Other options
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")

    return parser.parse_args(args)





def main():
    """Main entry point for the scan command."""
    args = parse_args()
    setup_logging(args.verbose)
    print_banner()

    if args.with_all:
        args.with_chps = True
        args.with_fips = True
        args.with_kevs = True

    orchestrator = GaugeOrchestrator(args)
    orchestrator.run()


def main_dispatch():
    """Main entry point with subcommand routing."""
    if len(sys.argv) > 1 and sys.argv[1] == "match":
        sys.argv.pop(1)
        main_match()
    else:
        main()


def main_match():
    """Match command entry point."""
    # This function remains large as it handles a separate command.
    # A similar refactoring could be applied to it in the future.
    parser = argparse.ArgumentParser(
        prog="gauge match",
        description="Match alternative container images to Chainguard equivalents",
    )
    # Simplified parser for brevity
    parser.add_argument("-i", "--input", type=Path, required=True, help="Input file with images.")
    parser.add_argument("-o", "--output", type=Path, default=Path("output/matched-log.csv"), help="Output CSV file.")
    parser.add_argument("--interactive", action="store_true", help="Enable interactive mode.")
    parser.add_argument("--github-token", type=str, help="GitHub token for issue search.")
    parser.add_argument("--min-confidence", type=float, default=DEFAULT_MATCH_CONFIDENCE, help="Minimum match confidence.")
    parser.add_argument("--dfc-mappings-file", type=Path, help="Local DFC mappings file.")
    parser.add_argument("--cache-dir", type=Path, help="Cache directory.")
    parser.add_argument("--skip-public-repo-search", action="store_true", help="Skip upstream discovery.")
    parser.add_argument("--upstream-confidence", type=float, default=DEFAULT_UPSTREAM_CONFIDENCE, help="Upstream match confidence.")
    parser.add_argument("--upstream-mappings-file", type=Path, help="Manual upstream mappings file.")
    parser.add_argument("--disable-llm-matching", action="store_true", help="Disable LLM matching.")
    parser.add_argument("--llm-model", type=str, default=DEFAULT_LLM_MODEL, help="Claude model for matching.")
    parser.add_argument("--llm-confidence-threshold", type=float, default=DEFAULT_LLM_CONFIDENCE, help="LLM match confidence.")
    parser.add_argument("--anthropic-api-key", type=str, help="Anthropic API key.")
    parser.add_argument("--generate-dfc-pr", action="store_true", help="Generate DFC contribution files.")
    parser.add_argument("--disable-mapping-auto-population", action="store_true", help="Disable auto-populating mappings.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")

    args = parser.parse_args()
    setup_logging(args.verbose)
    print_banner()
    logger = logging.getLogger(__name__)

    # Basic validation
    if not args.input.exists():
        logger.error(f"Input file not found: {args.input}")
        sys.exit(1)

    from commands.match import match_images
    try:
        _, unmatched_images = match_images(
            input_file=args.input,
            output_file=args.output,
            min_confidence=args.min_confidence,
            interactive=args.interactive,
            dfc_mappings_file=args.dfc_mappings_file,
            cache_dir=args.cache_dir,
            find_upstream=not args.skip_public_repo_search,
            upstream_confidence=args.upstream_confidence,
            upstream_mappings_file=args.upstream_mappings_file,
            enable_llm_matching=not args.disable_llm_matching,
            llm_model=args.llm_model,
            llm_confidence_threshold=args.llm_confidence_threshold,
            anthropic_api_key=args.anthropic_api_key,
            generate_dfc_pr=args.generate_dfc_pr,
            github_token=args.github_token,
        )
        if not unmatched_images:
            logger.info("All images matched successfully.")
    except Exception as e:
        logger.error(f"Match command failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main_dispatch()
