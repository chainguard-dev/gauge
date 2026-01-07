"""
Centralized configuration constants for Gauge.

This module provides a single source of truth for configuration values
that are used across multiple modules, making them easier to update
and maintain.
"""

# ============================================================================
# Platform and Architecture
# ============================================================================

DEFAULT_PLATFORM = "linux/amd64"
"""Default container platform architecture."""

# ============================================================================
# Financial / ROI Calculation Defaults
# ============================================================================

DEFAULT_HOURS_PER_VULNERABILITY = 3.0
"""Default estimated hours to remediate one CVE."""

DEFAULT_HOURLY_RATE = 100.0
"""Default engineering hourly rate in USD."""

CHAINGUARD_IMAGE_COST = 29000
"""Annual cost per Chainguard image subscription in USD."""

# ============================================================================
# Concurrency and Performance
# ============================================================================

DEFAULT_MAX_WORKERS = 2
"""Default number of concurrent workers for parallel scanning (reduced from 4 to reduce Docker daemon contention)."""

DEFAULT_CHPS_MAX_WORKERS = 2
"""Default number of concurrent workers for parallel CHPS scanning."""

# ============================================================================
# Image Matching Configuration
# ============================================================================

DEFAULT_MATCH_CONFIDENCE = 0.7
"""Default minimum confidence for automatic matching (0.0-1.0)."""

DEFAULT_UPSTREAM_CONFIDENCE = 0.7
"""Default minimum confidence for upstream discovery (0.0-1.0)."""

DEFAULT_LLM_CONFIDENCE = 0.7
"""Default minimum confidence for LLM fuzzy matching (0.0-1.0)."""

DEFAULT_ISSUE_MATCH_CONFIDENCE = 0.7
"""Default minimum confidence for GitHub issue matching (0.0-1.0)."""

DFC_CONTRIBUTION_THRESHOLD = 0.85
"""Minimum confidence for DFC contribution eligibility (0.0-1.0)."""

MANUAL_MAPPING_THRESHOLD = 0.85
"""Minimum confidence for auto-populating manual mappings (0.0-1.0)."""

# Matching tier confidences
MATCH_CONFIDENCE_DFC = 0.95
"""Confidence for DFC tier 1 matches."""

MATCH_CONFIDENCE_MANUAL = 1.0
"""Confidence for manual tier 2 matches."""

MATCH_CONFIDENCE_HEURISTIC = 0.85
"""Confidence for heuristic tier 3 matches."""

# ============================================================================
# LLM Configuration
# ============================================================================

DEFAULT_LLM_MODEL = "claude-sonnet-4-5"
"""Default Claude model for LLM matching."""

LLM_MODEL_OPTIONS = {
    "claude-sonnet-4-5": "Balanced performance and accuracy",
    "claude-opus-4-1": "Highest accuracy, slower",
    "claude-haiku-4-5": "Fastest, cheapest",
}
"""Available Claude models for LLM matching."""

# ============================================================================
# Registry Configuration
# ============================================================================

CHAINGUARD_PRIVATE_REGISTRY = "cgr.dev/chainguard-private"
"""Chainguard private registry prefix."""

CHAINGUARD_PUBLIC_REGISTRY = "cgr.dev/chainguard"
"""Chainguard public registry prefix."""

# Google Cloud Registry patterns
GCR_REGISTRIES = ["gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io"]
"""Google Container Registry hostnames."""

ARTIFACT_REGISTRY_SUFFIX = "pkg.dev"
"""Google Artifact Registry domain suffix."""

# ============================================================================
# Timeouts (in seconds)
# ============================================================================

SYFT_TIMEOUT = 600
"""Timeout for Syft SBOM generation (10 minutes)."""

GRYPE_TIMEOUT = 600
"""Timeout for Grype vulnerability scanning (10 minutes)."""

CHPS_TIMEOUT = 600
"""Timeout for CHPS scoring (10 minutes)."""

VERSION_CHECK_TIMEOUT = 5
"""Timeout for tool version checks (5 seconds)."""

API_REQUEST_TIMEOUT = 30
"""Timeout for general API requests (30 seconds)."""

KEV_CATALOG_TIMEOUT = 30
"""Timeout for KEV catalog download (30 seconds)."""

DOCKER_PULL_TIMEOUT = 600
"""Timeout for Docker image pull operations (10 minutes)."""

DOCKER_QUICK_CHECK_TIMEOUT = 5
"""Timeout for quick Docker status checks (5 seconds)."""

GITHUB_CLI_TIMEOUT = 10
"""Timeout for GitHub CLI operations (10 seconds)."""

GITHUB_ISSUE_SEARCH_TIMEOUT = 30
"""Timeout for GitHub issue search API requests (30 seconds)."""

GCR_AUTH_TIMEOUT = 30
"""Timeout for Google Cloud Registry authentication operations (30 seconds)."""

CLI_SUBPROCESS_TIMEOUT = 60
"""Timeout for general CLI subprocess operations (1 minute)."""

# ============================================================================
# CVE Monthly Occurrence Ratios
# ============================================================================

CVE_MONTHLY_RATIOS = {
    "CRITICAL": 0.06226879415733905,
    "HIGH": 0.048255074492743404,
    "MEDIUM": 0.09295663633080238,
    "LOW": 0.039432287834430285,
    "NEGLIGIBLE": 0.30331818635773494,
}
"""
Historical monthly CVE occurrence ratios by severity.

These represent the average monthly new CVE rate as a ratio of current CVEs,
derived from historical analysis of container image vulnerability trends.

USAGE NOTE: These static constants serve as FALLBACK values when dynamic
CVE growth rates cannot be fetched from the Chainguard API. The application
prefers to use real-time data via ChainguardAPI.calculate_cve_growth_rate()
when available (requires chainctl authentication). When the API is unavailable,
unreachable, or returns no data, these historical ratios are used instead.

See utils/cve_ratios.py:get_cve_monthly_ratios() for the fallback logic.
"""

# ============================================================================
# FIPS Phase Configurations
# ============================================================================

# These are imported from fips_calculator to avoid circular dependencies
# but documented here for reference. See utils.fips_calculator for details.

# ============================================================================
# External Service URLs
# ============================================================================

KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
"""URL for CISA Known Exploited Vulnerabilities catalog."""

CHAINGUARD_API_URL = "https://console-api.enforce.dev"
"""Base URL for Chainguard API services."""

CHPS_SCORER_IMAGE = "ghcr.io/chps-dev/chps-scorer:latest"
"""Docker image for CHPS (Container Hardening and Provenance Scanner)."""

# ============================================================================
# Resource Paths
# ============================================================================

CHAINGUARD_LOGO_PATH = "resources/linky-white.png"
"""Path to Chainguard logo for HTML reports."""

# ============================================================================
# CHPS Grade Mappings
# ============================================================================

GRADE_TO_CSS_CLASS = {
    "A+": "vuln-negligible",
    "A": "vuln-negligible",
    "B": "vuln-low",
    "C": "vuln-medium",
    "D": "vuln-high",
    "E": "vuln-critical",
    "F": "vuln-critical",
}
"""Mapping of CHPS letter grades to CSS color classes (without vuln-badge)."""
