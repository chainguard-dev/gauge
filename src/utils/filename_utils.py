"""
Utility functions for filename and customer name handling.
"""

import re


def sanitize_customer_name(name: str) -> str:
    """
    Sanitize customer name for use in filenames.

    Args:
        name: Raw customer name (e.g., "Acme Corp", "Test & Co.")

    Returns:
        Sanitized name suitable for filenames (e.g., "acme_corp", "test_co")
    """
    safe_name = name.replace("&", "").replace(".", "")
    safe_name = "".join(c if c.isalnum() or c in (" ", "-", "_") else "_" for c in safe_name)
    safe_name = safe_name.replace(" ", "_").lower()
    safe_name = re.sub(r"_+", "_", safe_name)
    return safe_name


def extract_registry_from_image(image: str) -> str:
    """
    Extract registry hostname from image reference.

    Args:
        image: Full image reference (e.g., "nginx:latest", "gcr.io/project/app:v1")

    Returns:
        Registry hostname. Returns "docker.io" for Docker Hub images.

    Examples:
        "nginx:latest" -> "docker.io"
        "library/nginx:latest" -> "docker.io"
        "registry1.dso.mil/ironbank/nginx:1.25" -> "registry1.dso.mil"
        "gcr.io/myproject/app:v1" -> "gcr.io"
        "ghcr.io/org/image:latest" -> "ghcr.io"
        "localhost:5000/myimage:dev" -> "localhost:5000"
    """
    # Remove digest first (after @)
    image_no_digest = image.split("@")[0]

    # No slash means it's a Docker Hub official image
    if "/" not in image_no_digest:
        return "docker.io"

    # Get the first part (potential registry)
    first_part = image_no_digest.split("/")[0]

    # Check if first part looks like a registry:
    # - Has dots (e.g., gcr.io, registry.company.com)
    # - Has colons (e.g., localhost:5000)
    # - Is "localhost"
    if "." in first_part or ":" in first_part or first_part == "localhost":
        return first_part

    # Otherwise it's a Docker Hub user/org image (e.g., "library/nginx", "myuser/myimage")
    return "docker.io"
