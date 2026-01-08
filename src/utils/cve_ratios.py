"""
CVE growth rate calculation with dynamic API fetching and static fallback.

Provides intelligent CVE monthly growth ratios by attempting to fetch real-time
data from the Chainguard API, falling back to historical static constants when
the API is unavailable or fails.
"""

import logging
from typing import Optional

from constants import CVE_MONTHLY_RATIOS

logger = logging.getLogger(__name__)

# Module-level cache for API results to avoid repeated calls
_ratios_cache: dict[str, dict[str, float]] = {}


def get_cve_monthly_ratios(
    image_name: Optional[str] = None,
    chainguard_image_name: Optional[str] = None,
    use_api: bool = True,
) -> dict[str, float]:
    """
    Get CVE monthly growth ratios with API fallback.

    This function attempts to fetch dynamic CVE growth rates from the Chainguard API
    for the corresponding Chainguard image, using that data as a proxy for estimating
    CVE growth in the alternative image. If the API call fails or returns no data,
    it falls back to historical static constants defined in constants.py.

    Args:
        image_name: Full alternative image reference (e.g., "python:3.12"). Used for logging.
        chainguard_image_name: Corresponding Chainguard image (e.g., "cgr.dev/chainguard/python:latest").
                              If provided, API will query this image's historical CVE data.
        use_api: Whether to attempt API call. Set to False to skip API and use static ratios.

    Returns:
        Dictionary mapping severity level to monthly growth ratio.
        Keys: "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"

    Example:
        >>> ratios = get_cve_monthly_ratios("python:3.12", "cgr.dev/chainguard/python:latest")
        >>> monthly_new_critical = current_critical_count * ratios["CRITICAL"]
    """
    # If API disabled or no chainguard image specified, use static fallback
    if not use_api or not chainguard_image_name:
        logger.debug("Using static CVE monthly ratios (fallback)")
        return CVE_MONTHLY_RATIOS

    # Try to fetch dynamic ratios from API using Chainguard image data
    try:
        from integrations.chainguard_api import ChainguardAPI

        # Parse Chainguard image name to extract repo and tag
        repo, tag = _parse_image_name(chainguard_image_name)
        if not repo or not tag:
            logger.debug(f"Could not parse Chainguard image name: {chainguard_image_name}, using static ratios")
            return CVE_MONTHLY_RATIOS

        # Check cache first (keyed by repo:tag)
        cache_key = f"{repo}:{tag}"
        if cache_key in _ratios_cache:
            logger.debug(f"Using cached CVE ratios for {cache_key}")
            return _ratios_cache[cache_key]

        # Initialize API client
        api = ChainguardAPI()

        # Fetch dynamic growth rates from Chainguard image
        dynamic_ratios = api.calculate_cve_growth_rate(repo, tag)

        if dynamic_ratios:
            image_desc = f"{image_name} (using {repo}:{tag} data)" if image_name else f"{repo}:{tag}"
            logger.info(f"Using dynamic CVE growth rates for {image_desc}")
            # Normalize the keys to match our expected format
            normalized = {
                "CRITICAL": dynamic_ratios.get("CRITICAL", CVE_MONTHLY_RATIOS["CRITICAL"]),
                "HIGH": dynamic_ratios.get("HIGH", CVE_MONTHLY_RATIOS["HIGH"]),
                "MEDIUM": dynamic_ratios.get("MEDIUM", CVE_MONTHLY_RATIOS["MEDIUM"]),
                "LOW": dynamic_ratios.get("LOW", CVE_MONTHLY_RATIOS["LOW"]),
                "NEGLIGIBLE": dynamic_ratios.get("UNKNOWN", CVE_MONTHLY_RATIOS["NEGLIGIBLE"]),
            }
            # Cache the result
            _ratios_cache[cache_key] = normalized
            return normalized
        else:
            image_desc = f"{image_name} ({repo}:{tag})" if image_name else f"{repo}:{tag}"
            logger.debug(f"No dynamic data available for {image_desc}, using static ratios")
            # Cache the fallback to avoid repeated failed API calls
            _ratios_cache[cache_key] = CVE_MONTHLY_RATIOS
            return CVE_MONTHLY_RATIOS

    except RuntimeError as e:
        # chainctl not available or not authenticated
        logger.debug(f"Cannot use Chainguard API: {e}")
        return CVE_MONTHLY_RATIOS
    except Exception as e:
        # Any other error - log and fall back
        logger.warning(f"Error fetching dynamic CVE ratios: {e}, using static fallback")
        return CVE_MONTHLY_RATIOS


def _parse_image_name(image_name: str) -> tuple[Optional[str], Optional[str]]:
    """
    Parse image name into repo and tag components.

    Args:
        image_name: Full image reference (e.g., "python:3.12" or "registry.io/repo/python:3.12")

    Returns:
        Tuple of (repo, tag). Returns (None, None) if parsing fails.

    Examples:
        >>> _parse_image_name("python:3.12")
        ("python", "3.12")
        >>> _parse_image_name("cgr.dev/chainguard/python:latest")
        ("python", "latest")
        >>> _parse_image_name("docker.io/library/nginx:1.25")
        ("nginx", "1.25")
    """
    try:
        # Handle case with no tag
        if ":" not in image_name:
            return None, None

        # Split on last colon to get tag
        parts = image_name.rsplit(":", 1)
        repo_path = parts[0]
        tag = parts[1]

        # Extract just the repo name (last component of path)
        # e.g., "cgr.dev/chainguard/python" -> "python"
        repo = repo_path.split("/")[-1]

        return repo, tag

    except (IndexError, AttributeError):
        return None, None
