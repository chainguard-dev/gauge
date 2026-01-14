# Contributing to Gauge

Thank you for your interest in contributing to Gauge! This document provides guidelines and information for developers working on the project.

## Table of Contents

- [Development Setup](#development-setup)
- [Project Architecture](#project-architecture)
- [Code Organization](#code-organization)
- [Design Principles](#design-principles)
- [Testing](#testing)
- [Code Style](#code-style)
- [Common Tasks](#common-tasks)
- [Pull Request Process](#pull-request-process)

## Development Setup

### Prerequisites

- Python 3.10 or higher
- Docker or Podman
- Grype and Syft (for vulnerability scanning)
- Git

### Local Development Installation

```bash
# Clone the repository
git clone <repository-url>
cd gauge

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -e .  # Install in editable mode

# Install optional dev tools
pip install pytest pytest-cov mypy black ruff
```

### Running Without Installation

```bash
# Using PYTHONPATH
PYTHONPATH=src python -m cli --help

# Or directly
python -m src.cli --help
```

## Project Architecture

Gauge is a unified container vulnerability assessment tool that generates three output types:
1. **Vulnerability Assessment Summary (HTML)** - Executive security reports
2. **Vulnerability Cost Analysis (XLSX)** - ROI and cost analysis
3. **Pricing Quotes (HTML)** - Subscription cost estimates

### Core Pipeline

```
CSV Input → Scanner → Cache Check → Syft (SBOM) → Grype (CVEs) → CHPS (Hardening) → KEV Detection → Report Generation
```

### Key Design Decisions

1. **Digest-based Caching**: Uses image SHA256 digests as cache keys for reliable caching
2. **Flag-aware Cache Validation**: Cache entries validated against CHPS/KEV/FIPS flags
3. **Plugin Architecture**: Scanner providers implement `VulnerabilityProvider` interface
4. **Immutable Data Models**: Frozen dataclasses prevent accidental mutation
5. **Modular Report Generation**: Separate generators for HTML and XLSX outputs
6. **Checkpoint/Resume**: Long-running scans can be interrupted and resumed
7. **Automatic Retry Queue**: Failed image pulls are automatically retried at the end of scans to handle transient network issues, rate limits, and temporary server problems

## Code Organization

### Directory Structure

```
gauge/
├── src/                              # Source code (Python best practice: src layout)
│   ├── core/                         # Core business logic
│   │   ├── cache.py                 # Digest-based caching with flag validation
│   │   ├── exceptions.py            # Custom exception hierarchy
│   │   ├── models.py                # Immutable data models (frozen dataclasses)
│   │   ├── persistence.py           # Checkpoint/resume functionality
│   │   ├── scanner.py               # Main scanner orchestration
│   │   └── scanner_interface.py    # Scanner plugin interface
│   ├── integrations/                # External service integrations
│   │   ├── chainguard_api.py       # Chainguard API client
│   │   ├── dfc_mappings.py         # DFC mappings fetcher from GitHub
│   │   ├── github_issue_search.py  # GitHub API for image request issues
│   │   ├── github_metadata.py      # GitHub image metadata for pricing tiers
│   │   ├── grype_provider.py       # Grype scanner implementation
│   │   └── kev_catalog.py          # CISA KEV catalog (O(1) lookups)
│   ├── outputs/                     # Report generation
│   │   ├── base.py                 # Base generator interface
│   │   ├── config.py               # Generator configuration dataclasses
│   │   ├── html_generator.py      # HTML vulnerability assessment reports
│   │   ├── pricing_quote_generator.py  # HTML pricing quotes
│   │   ├── styles.css              # External CSS (851 lines)
│   │   ├── xlsx_formats.py         # XLSX formatting factory
│   │   ├── xlsx_generator.py      # XLSX cost analysis reports
│   │   └── xlsx_writers.py         # Modular XLSX section writers
│   ├── utils/                       # Utility modules
│   │   ├── chps_utils.py           # Container hardening integration
│   │   ├── cve_ratios.py           # CVE growth rate calculations
│   │   ├── dfc_contributor.py      # DFC contribution file generation
│   │   ├── docker_utils.py         # Docker/Podman abstraction
│   │   ├── fips_calculator.py      # FIPS cost calculations
│   │   ├── formatting.py           # Number, date, currency formatting
│   │   ├── gcr_auth.py             # Google Cloud Registry authentication
│   │   ├── image_classifier.py     # Image tier classification
│   │   ├── image_matcher.py        # Multi-tier image matching orchestration
│   │   ├── image_utils.py          # Image name parsing utilities
│   │   ├── image_verification.py   # Centralized Chainguard image verification
│   │   ├── issue_matcher.py        # LLM-powered GitHub issue matching
│   │   ├── llm_matcher.py          # Claude LLM integration for Tier 4
│   │   ├── logging_helpers.py      # Consistent logging utilities
│   │   ├── manual_mapping_populator.py  # Auto-populate manual mappings
│   │   ├── markdown_utils.py       # Markdown loading and conversion
│   │   ├── metrics_calculator.py   # CVE reduction metrics
│   │   ├── pricing_calculator.py   # Pricing quote calculations
│   │   ├── roi_calculator.py       # ROI and cost projections
│   │   ├── token_manager.py        # Docker registry token management
│   │   ├── upstream_finder.py      # Multi-strategy upstream discovery
│   │   ├── validation.py           # Input validation
│   │   └── vulnerability_utils.py  # Vulnerability aggregation
│   ├── cli.py                       # Command-line interface entry point
│   └── constants.py                 # Centralized configuration (timeouts, defaults)
├── tests/                            # Unit and integration tests
│   ├── conftest.py                  # Shared pytest fixtures
│   ├── test_*.py                    # Test modules (419 tests)
│   └── ...
├── config/                           # Configuration files
│   └── image_tiers.yaml             # Cached image tier mappings
├── resources/                        # Static assets
│   ├── gauge-logo-*.png            # Branding assets
│   └── linky-white.png             # Chainguard logo
├── example-images.csv               # Sample input
├── sample-exec-summary.md           # Template example
├── sample-appendix.md               # Template example
├── example-pricing-policy.yaml      # Pricing policy example
├── requirements.txt                 # Python dependencies
├── setup.py                         # Package configuration
├── pytest.ini                       # Test configuration
├── Dockerfile                       # Container build
├── README.md                        # User documentation
├── MIGRATION.md                     # Legacy tool migration guide
└── CONTRIBUTING.md                  # This file
```

### Module Responsibilities

#### Core Modules (`src/core/`)

**`scanner.py`** - Main orchestration
- Coordinates Syft → Grype → CHPS → KEV pipeline
- Manages parallel scanning with thread pool
- Handles image freshness checking
- Integrates with caching system
- Automatic retry queue for failed image pulls

**`cache.py`** - Performance optimization
- Digest-based cache keys (SHA256)
- Strict flag validation (CHPS/KEV/FIPS)
- Platform-aware caching
- Cache statistics and management

**`models.py`** - Data structures
- `ImageAnalysis`: Scan results for one image
- `ScanResult`: Pair comparison results
- `VulnerabilityCount`: Severity breakdown
- `CHPSScore`: Container hardening metrics
- All models are frozen dataclasses (immutable)

**`persistence.py`** - Checkpoint/resume
- Automatic progress saving
- Safe interruption handling
- Resume from checkpoint
- JSON-based format

**`exceptions.py`** - Error handling
- Custom exception hierarchy
- Semantic error types
- Consistent error messages

**`retry_queue.py`** - Error recovery
- Tracks failed image pulls for retry
- Automatic retry at end of scan run
- Handles transient network/rate limit errors
- In-memory queue with context tracking

**`scanner_interface.py`** - Plugin system
- `VulnerabilityProvider` abstract base
- Extensible scanner integration
- Consistent interface for providers

#### Integrations (`src/integrations/`)

**`grype_provider.py`** - CVE scanning
- Implements `VulnerabilityProvider` interface
- Executes Grype with Syft SBOM
- Parses JSON output
- Error handling and timeouts

**`chainguard_api.py`** - API client
- Fetches CVE growth rates
- Fallback to static data
- Caching for performance

**`github_metadata.py`** - Image metadata
- GitHub API integration
- Token management (gh CLI, env var, explicit)
- Image tier classification
- SAML SSO handling

**`kev_catalog.py`** - KEV detection
- CISA catalog fetching
- O(1) CVE lookups with dictionary
- Detailed KEV entry information

**`dfc_mappings.py`** - DFC mappings
- Fetches DFC image mappings from GitHub
- Parses YAML configuration
- Caching for performance

**`github_issue_search.py`** - Issue search
- GitHub API client for image request issues
- Searches chainguard-dev/image-requests repository
- Returns issue metadata and URLs

#### Outputs (`src/outputs/`)

**`html_generator.py`** - Assessment reports
- Professional HTML generation
- Markdown integration (exec summary, appendix)
- Template variable substitution
- CVE reduction visualizations
- CHPS and KEV sections
- External CSS loading

**`pricing_quote_generator.py`** - Pricing quotes
- Tier-based pricing calculations
- Volume discount application
- HTML quote generation
- Line item formatting

**`xlsx_generator.py`** - Cost analysis
- ROI calculations
- CVE cost projections
- FIPS cost analysis
- Interactive formulas
- Modular section writing

**`xlsx_writers.py`** - XLSX components
- `ImageDataWriter`: Image comparison tables
- `CostAnalysisWriter`: ROI calculations
- `CHPSWriter`: CHPS scoring tables
- Single-responsibility principle

**`xlsx_formats.py`** - Styling
- Format factory pattern
- Consistent styles across workbook
- Eliminates duplication

#### Utilities (`src/utils/`)

**`formatting.py`** - Display formatting
- Number formatting with commas
- Currency formatting (cents → dollars)
- Percentage formatting
- Date formatting with ordinals

**`logging_helpers.py`** - Consistent logging
- Error section formatting
- Warning section formatting
- Separator line utilities

**`markdown_utils.py`** - Markdown processing
- File loading
- Template variable substitution
- Markdown → HTML conversion

**`validation.py`** - Input validation
- Image reference validation
- File path validation
- Number range validation
- Customer name validation

**`metrics_calculator.py`** - CVE metrics
- Vulnerability aggregation
- Reduction calculations
- Statistical metrics

**`pricing_calculator.py`** - Pricing logic
- Policy loading and parsing
- Tier cost calculations
- Volume discount application
- Quote generation

**`image_classifier.py`** - Tier classification
- GitHub metadata integration
- Local cache management
- Automatic tier detection

**`docker_utils.py`** - Container operations
- Docker/Podman abstraction
- Intelligent fallback strategies (mirror.gcr.io, :latest tag)
- Image pulling and inspection with timeout handling
- Platform handling
- Recoverable error detection for retry queue

**`gcr_auth.py`** - Google Cloud Registry authentication
- Service account JSON credential support
- gcloud Application Default Credentials (ADC) fallback
- Docker credential configuration
- Registry pattern detection (gcr.io, pkg.dev)

**`image_verification.py`** - Chainguard image verification
- Centralized verification service
- Two-tier verification (GitHub API → Docker fallback)
- Used by image matching tiers 3 and 4
- Eliminates duplicate verification code

**`chps_utils.py`** - Container hardening
- Containerized CHPS execution
- Score parsing and validation
- Component scoring breakdown

**`dfc_contributor.py`** - DFC contribution
- Generates DFC PR contribution files
- YAML and patch file creation
- High-confidence match extraction

**`filename_utils.py`** - Filename utilities
- Customer name sanitization for filenames
- Registry extraction from image references
- Used by match command for summary CSV generation

**`image_matcher.py`** - Image matching orchestration
- 4-tier matching strategy coordination
- Confidence scoring and method tracking
- Match result aggregation

**`image_utils.py`** - Image utilities
- Image name parsing and normalization
- Registry prefix handling
- Tag extraction

**`issue_matcher.py`** - GitHub issue matching
- LLM-powered matching of images to existing GitHub issues
- Searches chainguard-dev/image-requests repository
- Returns confidence scores and issue URLs

**`llm_matcher.py`** - AI image matching
- Claude LLM integration for Tier 4 fuzzy matching
- Catalog-based Chainguard image suggestions
- Automatic verification of suggested images

**`manual_mapping_populator.py`** - Mapping population
- Auto-populates manual mappings with new discoveries
- YAML file management
- Deduplication handling

**`token_manager.py`** - Registry authentication
- Docker registry token management
- Automatic token refresh
- Multi-registry support (Docker Hub, GCR, etc.)

**`upstream_finder.py`** - Upstream discovery
- Multi-strategy upstream image discovery
- Supports gcr.io, docker.io, quay.io, ghcr.io
- Registry stripping and base extraction strategies

## Design Principles

### 1. SOLID Principles

- **Single Responsibility**: Each module has one clear purpose
- **Open/Closed**: Plugin interface allows extension without modification
- **Liskov Substitution**: Scanner providers are interchangeable
- **Interface Segregation**: Small, focused interfaces
- **Dependency Inversion**: Depend on abstractions, not concretions

### 2. Immutability

All data models use `@dataclass(frozen=True)` to prevent accidental mutation:

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class ImageAnalysis:
    image: str
    digest: str
    vulnerabilities: VulnerabilityCount
    # Cannot be modified after creation
```

### 3. Type Safety

Comprehensive type hints throughout:

```python
def calculate_metrics(results: list[ScanResult]) -> dict[str, Any]:
    """Calculate CVE reduction metrics."""
    ...
```

### 4. Error Handling

Custom exception hierarchy for semantic errors:

```python
class GaugeException(Exception):
    """Base exception for all Gauge errors."""

class ScanException(GaugeException):
    """Scanning operation failed."""

class CacheException(GaugeException):
    """Cache operation failed."""
```

**Retry Queue for Transient Failures:**

Failed image pulls (network issues, rate limits, temporary server problems) are automatically tracked and retried at the end of each scan run:

```python
# During scan: failed pulls are added to retry queue
scanner.scan_image("python:3.12", context="alternative", pair_index=0)
# If pull fails → added to retry queue

# After all scans complete: automatic retry processing
results = scanner.scan_image_pairs_parallel(pairs)
# Retry queue is processed automatically
# Successful retries update the results
```

Key features:
- **Single retry**: Each image gets exactly 1 retry (total 2 attempts)
- **End-of-run timing**: Maximizes time between attempts
- **Context tracking**: Knows which image pair and role failed
- **Result updates**: Successful retries update scan results in-place

### 5. Performance

- **Caching**: Digest-based cache eliminates redundant scans
- **Parallelism**: Multi-threaded scanning
- **O(1) Lookups**: Dictionaries for KEV and tier mappings
- **Efficient SBOM Reuse**: Single Syft execution per image

### 6. Modularity

- Extracted utilities for reusability
- Clear module boundaries
- Minimal coupling between components
- Easy to test in isolation

### 7. Modern Python

- Uses `src/` layout (PEP 420)
- Type hints (PEP 484)
- Dataclasses (PEP 557)
- Path objects instead of strings
- Context managers for resource cleanup

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_models.py

# Run verbose
pytest -v

# Run only fast tests
pytest -m unit
```

### Test Organization

- **Unit Tests**: Test individual functions/classes in isolation
- **Integration Tests**: Test component interactions
- **Fixtures**: Shared test data in `conftest.py`

### Writing Tests

```python
import pytest
from core.models import VulnerabilityCount

class TestVulnerabilityCount:
    """Tests for VulnerabilityCount model."""

    def test_create_empty(self):
        """Test creating empty vulnerability count."""
        vuln = VulnerabilityCount()
        assert vuln.total == 0

    def test_immutable(self):
        """Test that model is immutable."""
        vuln = VulnerabilityCount(critical=5)
        with pytest.raises(AttributeError):
            vuln.critical = 10
```

### Test Coverage

Current coverage: **419 tests passing**

## Code Style

### Formatting

- **Line Length**: 100 characters (flexible for readability)
- **Imports**: Grouped (stdlib, third-party, local)
- **Docstrings**: Google style
- **Naming**: `snake_case` for functions/variables, `PascalCase` for classes

### Documentation

```python
def calculate_cost(vulns: int, hours_per_vuln: float, hourly_rate: float) -> float:
    """
    Calculate remediation cost for vulnerabilities.

    Args:
        vulns: Number of vulnerabilities
        hours_per_vuln: Average hours to fix one vulnerability
        hourly_rate: Engineering hourly rate in USD

    Returns:
        Total remediation cost in USD

    Examples:
        >>> calculate_cost(100, 3.0, 100.0)
        30000.0
    """
    return vulns * hours_per_vuln * hourly_rate
```

### Type Hints

Always use type hints for function signatures:

```python
from typing import Optional, List, Dict

def process_images(
    images: List[str],
    cache_dir: Optional[Path] = None
) -> Dict[str, ImageAnalysis]:
    """Process list of images."""
    ...
```

## Common Tasks

### Adding a New Utility Function

1. Choose appropriate module in `src/utils/` (or create new one)
2. Add function with type hints and docstring
3. Write tests in `tests/test_<module>.py`
4. Import in relevant modules

### Adding a New Output Format

1. Create generator in `src/outputs/`
2. Inherit from `BaseGenerator` if applicable
3. Implement generation logic
4. Add CLI option in `src/cli.py`
5. Add tests
6. Update documentation

### Adding a New Scanner Provider

1. Create provider in `src/integrations/`
2. Implement `VulnerabilityProvider` interface
3. Register in scanner initialization
4. Add tests
5. Update documentation

### Refactoring

When refactoring, follow these priorities:

1. **Extract duplicated code** into utilities
2. **Consolidate similar patterns** into reusable functions
3. **Simplify complex functions** by breaking into smaller pieces
4. **Add type hints** where missing
5. **Improve error messages** for clarity
6. **Maintain backward compatibility** when possible

Recent refactoring examples:
- Consolidated `format_currency()` and `format_number()` into `utils/formatting.py`
- Extracted markdown loading into `utils/markdown_utils.py`
- Created logging helpers in `utils/logging_helpers.py`
- Extracted duplicate image verification into `utils/image_verification.py` (eliminated ~60 lines)
- Standardized timeout constants in `constants.py` (10+ hardcoded values → centralized constants)

## Pull Request Process

### Before Submitting

1. **Run tests**: `pytest` - all tests must pass
2. **Check types**: `mypy src/` (if available)
3. **Format code**: `black src/` (if available)
4. **Update documentation**: README.md, docstrings, etc.
5. **Add tests**: For new features or bug fixes

### PR Description

Include:
- **What**: Brief description of changes
- **Why**: Problem being solved or feature being added
- **How**: Technical approach
- **Testing**: How you tested the changes
- **Breaking Changes**: Any backward incompatibilities

### Review Process

1. Submit PR with clear description
2. Respond to review feedback
3. Make requested changes
4. Ensure CI passes (if configured)
5. Maintainer will merge when ready

## Questions?

For questions or discussion:
- Open an issue for bugs or feature requests
- Discussion forums or Slack (if available)
- Email maintainers (see README for contacts)

---

Thank you for contributing to Gauge!
