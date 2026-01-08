"""
Gauge - Container Vulnerability Assessment Tool

Gauge your container security posture with comprehensive vulnerability reports
comparing container images with Chainguard alternatives.
"""

__version__ = "1.6.0"
__author__ = "Chainguard"

from core.models import (
    ImageAnalysis,
    ScanResult,
    VulnerabilityCount,
    ImagePair,
)

__all__ = [
    "ImageAnalysis",
    "ScanResult",
    "VulnerabilityCount",
    "ImagePair",
]
