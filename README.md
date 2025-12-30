# Gauge

**Gauge your container security posture** - A unified tool for comprehensive container vulnerability assessments comparing the risks, the costs, and the "hardeness" (via [CHPs](https://github.com/chps-dev/chps)) of other container images as compared to [Chainguard Containers](https://www.chainguard.dev/containers).

<table width="100%" border="0" cellpadding="0" cellspacing="0">
<tr>
<td width="40%" valign="top">

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Input Format](#input-format)
- [Command-Line Options](#command-line-options)
- [Caching System](#caching-system)
- [Performance](#performance)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [Development](#development)
- [Migration from Legacy Tools](#migration-from-legacy-tools)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

</td>
<td width="60%" valign="middle" align="center">

<img src="resources/gauge-logo-white.png" width="600" alt="Gauge Logo">

</td>
</tr>
</table>

## Features

### Core Capabilities
- **Automatic Image Matching**: Automatically find Chainguard equivalents for your images using a 4-tier matching strategy with AI-powered fuzzy matching (DFC mappings, manual overrides, heuristics, Claude LLM)
- **Multiple Output Types**: Generate vulnerability summaries (HTML), cost analysis (XLSX), or pricing quotes (HTML + TXT)
- **CHPs Scoring**: Container Hardening and Provenance Scanner integration for evaluating non-CVE security factors like provenance, SBOM quality, signing, and container hardening practices
- **KEV Detection**: Optional integration with CISA's Known Exploited Vulnerabilities catalog to identify actively exploited CVEs in your images
- **Intelligent Caching**: Digest-based caching with exact flag matching dramatically improves performance on repeated scans
- **Checkpoint/Resume**: Automatically save progress and resume interrupted scans without losing work
- **Parallel Scanning**: Multi-threaded image scanning for optimal performance
- **Comprehensive Analysis**: Detailed vulnerability breakdowns by severity (Critical, High, Medium, Low, Negligible)

### Vulnerability Assessment Summary (HTML)
- Professional PDF-optimized assessment reports with Chainguard branding
- Executive summaries from markdown files
- Custom appendix support for organization-specific content
- CVE reduction metrics and visual comparisons
- Side-by-side image vulnerability analysis
- Focus: Security posture overview and vulnerability findings

### Vulnerability Cost Analysis (XLSX)
- Detailed ROI calculations for Chainguard adoption
- CVE backlog remediation cost estimates
- Projected future CVE costs based on historical data
- Optional FIPS implementation cost analysis
- Auto-detection of FIPS images
- Interactive formulas for scenario planning
- Focus: Financial planning and business case development

### Pricing Quote (HTML + TXT)
- Automated pricing quotes based on Chainguard image tiers (base, application, fips, ai)
- Automatic image tier classification via GitHub metadata
- Volume-based pricing with bulk discounts
- Configurable pricing policies per customer/partner
- Professional HTML quotes with customer branding and plain text versions for email
- Includes policy details, line items, and totals
- Focus: Sales enablement and subscription estimates

## Prerequisites

- **Python**: 3.10 or higher
- **Docker or Podman**: Container runtime for image operations
- **Grype**: Vulnerability scanner
  ```bash
  # macOS
  brew install anchore/grype/grype

  # Linux
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
  ```
- **Syft**: SBOM generator
  ```bash
  # macOS
  brew install syft

  # Linux
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  ```

## Installation

### Option 1: Container (Recommended)

Run Gauge in a container built with Chainguard Images:

```bash
# Authenticate to Chainguard registry (required for build and runtime)
chainctl auth login
chainctl auth configure-docker

# Build the container (requires authentication to cgr.dev/chainguard-private)
docker build -t gauge:latest .

# Run with your images CSV
docker run --rm \
  -v $(pwd):/workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v ~/.docker:/root/.docker:ro \
  -v ~/.config/chainctl:/root/.config/chainctl:ro \
  gauge:latest \
  --input /workspace/images.csv \
  --output both \
  --output-dir /workspace \
  --customer "Customer Name"
```

**Important requirements**:
- **Docker socket mount** (`-v /var/run/docker.sock:/var/run/docker.sock`): Required for pulling and scanning images, and CHPS scoring
- **Docker config mount** (`-v ~/.docker:/root/.docker:ro`): Required for registry authentication. The Docker CLI inside the container needs access to your credential configuration.
- **Chainctl config mount** (`-v ~/.config/chainctl:/root/.config/chainctl:ro`): Required for the credential helper to authenticate with cgr.dev registries.
- **Pre-authentication**: Run `chainctl auth login` and `chainctl auth configure-docker` on your host before building or running the container.

### Option 2: Local Installation

```bash
# Clone the repository
cd gauge

# Install dependencies
pip install -r requirements.txt

# Install as a package (recommended)
pip install -e .
```

## Quick Start

### Simplest Usage (with defaults)

With sensible defaults, you can run Gauge with minimal configuration:

```bash
gauge
```

This will:
- Read from `images.csv`
- Generate both `gauge_output.html` and `gauge_output.xlsx`
- Use `exec-summary.md` and `appendix.md` if they exist
- Use default ROI parameters (3 hours/CVE, $100/hour)

### Generate Vulnerability Cost Analysis (XLSX)

Generate a comprehensive cost analysis with ROI calculations:

```bash
gauge --output cost_analysis \
      --output-dir ./reports \
      --customer "Acme Corp"
```

This generates `./reports/acme_corp.xlsx`.

### Generate Vulnerability Assessment Summary (HTML)

Generate an executive assessment summary report:

```bash
gauge --output vuln_summary \
      --output-dir ./reports \
      --customer "Acme Corp"
```

This generates `./reports/acme_corp.html`.

### Generate Both Outputs

Generate both assessment summary (HTML) and cost analysis (XLSX):

```bash
gauge --output both \
      --output-dir ./reports \
      --customer "Acme Corp"
```

This generates both `./reports/acme_corp.html` and `./reports/acme_corp.xlsx`.

### With FIPS Cost Analysis

Add FIPS implementation cost calculations (XLSX only):

```bash
gauge --output cost_analysis \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --with-fips
```

This will auto-detect FIPS images from their names and create `cost-analysis.xlsx` with FIPS cost analysis included.

### With CHPS Hardening & Provenance Scoring

Include CHPS (Container Hardening and Provenance Scanner) scoring:

```bash
gauge --output both \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --with-chps
```

This will include CHPS scores in both HTML and XLSX outputs. CHPS evaluates non-CVE security factors like provenance, SBOM quality, signing, and container hardening practices.

**Note:** CHPS runs in a container automatically. The first time you use `--with-chps`, the tool will pull the `ghcr.io/chps-dev/chps-scorer:latest` image. No local installation required!

### With Known Exploited Vulnerabilities (KEV) Detection

Check CVEs against CISA's Known Exploited Vulnerabilities catalog:

```bash
gauge --output both \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --with-kevs
```

This will fetch CISA's KEV catalog and identify which CVEs in your images are actively being exploited in the wild. KEVs are highlighted with red badges in HTML reports and red cells in XLSX reports, making them easy to spot for prioritization.

**Note:** The KEV catalog is fetched from CISA on each run when `--with-kevs` is enabled. This ensures you always have the most up-to-date list of exploited vulnerabilities.

### CVE Severity Filtering

By default, Negligible and Unknown severity CVEs are excluded from reports and totals. Use `--include-negligible` to include them:

```bash
# Default: excludes Negligible/Unknown
gauge --input images.csv
# Output: nginx - 325 CVEs

# With flag: includes all severities  
gauge --input images.csv --include-negligible
# Output: nginx - 847 CVEs (includes 522 Negligible)
```

### Enable All Optional Features

Use `--with-all` as a shortcut to enable CHPS scoring, FIPS detection, and KEV tracking all at once:

```bash
gauge --output both \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --with-all
```

This is equivalent to: `--with-chps --with-fips --with-kevs`

### Custom Platform Specification

Override the default platform for specialized environments:

```bash
gauge --platform linux/arm64 \
      --output-dir ./reports \
      --customer "Acme Corp"
```

**Default behavior**: Gauge uses `linux/amd64` by default to ensure consistent results across all environments (including Apple Silicon Macs). This ensures that:
- Vulnerability scans are reproducible
- CHPS scores match direct CHPS execution
- Reports display the same platform across all scans

## Input Format

### Two-Column CSV (Manual Pairing)

Create a CSV file with explicit image pairs:

```csv
alternative_image,chainguard_image
python:3.12,cgr.dev/chainguard-private/python:latest
nginx:1.25,cgr.dev/chainguard-private/nginx:latest
postgres:16,cgr.dev/chainguard-private/postgres:latest
```

Optional header row is automatically skipped.

### Single-Column CSV (Automatic Matching)

Alternatively, provide just alternative images and let Gauge automatically find Chainguard equivalents:

```csv
alternative_image
python:3.12
nginx:1.25
postgres:16
```

When a single-column CSV is detected, Gauge uses a 4-tier matching strategy:
1. **DFC Mappings** (95% confidence) - Chainguard's Docker File Converter built-in mappings
2. **Manual Overrides** (100% confidence) - Local overrides in `config/image_mappings.yaml`
3. **Heuristic Rules** (85% confidence) - Pattern-based matching with image verification
4. **LLM-Powered Fuzzy Matching** (70%+ confidence) - Claude AI for complex image name transformations (enabled by default)

Gauge will show the matched pairs and warn about any unmatched images. Only images with ≥70% confidence are included in the scan.

You can control the matching behavior with CLI options:

```bash
# Upstream discovery enabled by default (use --skip-public-repo-search to disable)
gauge --input alternative-images.csv

# Scan with LLM matching disabled (Tiers 1-3 only)
gauge --input alternative-images.csv --disable-llm-matching

# Scan with custom confidence threshold
gauge --input alternative-images.csv --min-confidence 0.85

# Scan and generate DFC contribution files for new mappings
gauge --input alternative-images.csv --generate-dfc-pr
```

All matching options available in `gauge match` (see below) can also be used with the default `gauge` command for single-column CSV input.

### Standalone Matching (Preview Mode)

To preview matches without running a full scan, use the `gauge match` command:

```bash
# Match images and save to CSV
gauge match --input images.txt -o matched.csv

# With minimum confidence threshold
gauge match --input images.txt -o matched.csv --min-confidence 0.85

# Interactive mode for low-confidence matches
gauge match --input images.txt -o matched.csv --interactive

# Use offline DFC mappings
gauge match --input images.txt -o matched.csv --dfc-mappings-file local-mappings.yaml
```

The `match` command outputs:
- `matched.csv` - Successfully matched image pairs with full metadata (ready for scanning)
- `unmatched.txt` - Images that couldn't be matched (only if there are unmatched images)

### Upstream Image Discovery (For Private/Internal Images)

**Enabled by default**, Gauge automatically finds public upstream equivalents for images hosted in private registries or with internal names before matching to Chainguard:

```bash
# Upstream discovery is enabled by default - no flag needed
gauge match --input images.txt -o matched.csv

# Skip upstream discovery if not needed (faster for public images)
gauge match --input images.txt -o matched.csv --skip-public-repo-search

# With custom confidence thresholds
gauge match --input images.txt -o matched.csv --upstream-confidence 0.8

# Use manual upstream mappings for custom overrides
gauge match --input images.txt -o matched.csv --upstream-mappings-file config/upstream_mappings.yaml
```

**How it works:**
1. Input: `mycompany.io/python-app:v1` or `internal-nginx:prod`
2. **First Priority**: Check DFC and Manual Chainguard mappings with original image name
   - If explicit mapping exists (DFC or Manual), use it immediately
   - This ensures manual overrides take precedence over upstream discovery
3. **Fallback**: If no explicit mapping found, try Upstream Discovery (4 strategies):
   - **Manual Mappings** (100%) - Custom overrides in `config/upstream_mappings.yaml`
   - **Registry Strip** (90%) - Removes private registry prefix: `mycompany.io/python:3.12` → `python:3.12`
   - **Common Registries** (80%) - Checks docker.io, quay.io, ghcr.io
   - **Base Extraction** (70%) - Extracts base image: `internal-python-app` → `python:latest`
4. **Chainguard Matching**: Try all 4 tiers with upstream image (or original if no upstream found)
5. Output: Full audit trail in `matched.csv` showing both upstream and Chainguard matches

**Output format with upstream discovery:**
```csv
alternative_image,upstream_image,chainguard_image,upstream_confidence,match_confidence,upstream_method,match_method
mycompany.io/python:3.12,python:3.12,cgr.dev/chainguard/python:latest,0.90,0.95,registry_strip,dfc
```

**Manual upstream mappings** (`config/upstream_mappings.yaml`):
```yaml
# Map private/internal images to public upstream equivalents
"company.io/python-app:v1": "python:3.12"
"internal-nginx:prod": "nginx:1.25"
"gcr.io/myproject/redis:latest": "redis:7.0"
```

### LLM-Powered Fuzzy Matching (Tier 4)

**NEW:** Gauge now includes AI-powered image matching using Claude, enabled by default as Tier 4 fuzzy matching. This dramatically improves match rates for complex image names that can't be handled by rule-based heuristics.

**Features:**
- Uses Claude API for intelligent image name transformations
- **Automatic verification** - All LLM suggestions are verified to exist before acceptance (prevents hallucinations)
- Automatic caching to reduce API costs
- Telemetry logging for match rate analysis
- Configurable model selection (Sonnet, Opus, Haiku)
- Special rules for OS images (debian, ubuntu, rhel → chainguard-base)
- DFC contribution workflow for discovered mappings

**Basic Usage:**

```bash
# LLM matching is enabled by default
gauge match --input images.txt -o matched.csv

# Disable LLM matching (use only Tiers 1-3)
gauge match --input images.txt -o matched.csv --disable-llm-matching

# Use specific Claude model
gauge match --input images.txt -o matched.csv --llm-model claude-3-opus-20240229

# Adjust confidence threshold
gauge match --input images.txt -o matched.csv --llm-confidence-threshold 0.8

# Generate DFC contribution files for high-confidence matches
gauge match --input images.txt -o matched.csv --generate-dfc-pr
```

**Configuration:**

Set your Anthropic API key:
```bash
export ANTHROPIC_API_KEY='your-api-key'
# Or pass directly
gauge match --input images.txt --anthropic-api-key 'your-api-key'
```

Get an API key at: https://console.anthropic.com/

**Model Options:**
- `claude-sonnet-4-5` (default) - Best balance of speed and accuracy
- `claude-opus-4-1` - Highest accuracy, slower, more expensive
- `claude-haiku-4-5` - Fastest, cheapest, lower accuracy

**DFC Contribution Workflow:**

When `--generate-dfc-pr` is enabled, Gauge generates two files for contributing new mappings back to the DFC project. This includes **both Tier 3 heuristic matches and Tier 4 LLM matches** with high confidence (≥85%):

- `dfc-suggestions.yaml` - Suggested mappings with metadata (method, confidence, reasoning)
- `dfc-suggestions.patch` - Git diff ready for PR creation

```bash
gauge match --input images.txt -o matched.csv --generate-dfc-pr

# Generated files include successful heuristic and LLM matches:
# - dfc-suggestions.yaml (mappings to review)
# - dfc-suggestions.patch (git diff for PR)
```

**Why contribute back?** If Gauge found a match that's not in DFC yet (via heuristics or LLM), other users can benefit from it being added to the official DFC mappings.

**Cache and Telemetry:**

LLM responses are cached in `~/.cache/gauge/` to reduce API costs:
- `llm_cache.db` - SQLite database of cached responses
- `llm_telemetry.jsonl` - Match attempts, successes, latency metrics

**Example Output:**
```
[1/10] ✓ Matched: ghcr.io/kyverno/background-controller:v1.10.3 → cgr.dev/chainguard-private/kyverno-background-controller:latest
    (confidence: 85%, method: llm)
    LLM reasoning: Kyverno background controller is a Kubernetes policy engine component with a direct Chainguard equivalent using hyphenated naming convention
```

See `gauge match --help` for all options.

## Command-Line Options

### Input/Output Options

| Option | Default | Description |
|--------|---------|-------------|
| `-i, --input` | `images.csv` | Input CSV file with image pairs or single-column alternative images |
| `-o, --output` | `vuln_summary,cost_analysis` | Output types to generate (comma-separated): `cost_analysis` (XLSX), `vuln_summary` (HTML), `pricing` (HTML + TXT). Examples: `--output pricing`, `--output cost_analysis,pricing`, `--output vuln_summary,cost_analysis,pricing` |
| `--output-dir` | `.` (current directory) | Output directory for generated reports |
| `--pricing-policy` | `pricing-policy.yaml` | Pricing policy file for quote generation (see [Pricing Configuration](#pricing-configuration)) |

### Common Options

| Option | Default | Description |
|--------|---------|-------------|
| `-c, --customer` | "Customer" | Customer name for report branding |
| `--max-workers` | 4 | Number of parallel scanning threads |
| `--platform` | `linux/amd64` | Platform for image pulls and scans (ensures consistency across all environments including ARM64 Macs) |
| `--include-negligible` | - | Include Negligible/Unknown severity CVEs in total counts and reports (excluded by default) |
| `-v, --verbose` | - | Enable verbose logging |

### Assessment Summary Options (HTML)

| Option | Default | Description |
|--------|---------|-------------|
| `-e, --exec-summary` | `exec-summary.md` | Markdown file for executive summary (optional if file doesn't exist) |
| `-a, --appendix` | `appendix.md` | Markdown file for custom appendix (optional if file doesn't exist) |

#### Template Variables for Executive Summary and Appendix

Both the executive summary and appendix markdown files support template variable substitution. Use `{{variable_name}}` syntax to insert dynamic values:

**Basic Metrics:**
- `{{customer_name}}` - Customer name from `--customer` flag
- `{{images_scanned}}` - Total number of images analyzed
- `{{total_customer_vulns}}` - Total CVEs in customer/alternative images
- `{{total_chainguard_vulns}}` - Total CVEs in Chainguard images
- `{{total_reduction}}` - Total CVE reduction (customer - chainguard)
- `{{reduction_percentage}}` - CVE reduction as percentage (with % sign)
- `{{images_with_reduction}}` - Number of images where Chainguard has fewer CVEs
- `{{average_reduction_per_image}}` - Average CVE reduction per image

**KEV Metrics** (available when using `--with-kevs` flag):
- `{{total_customer_kevs}}` - Total Known Exploited Vulnerabilities in customer images
- `{{total_chainguard_kevs}}` - Total KEVs in Chainguard images
- `{{kev_reduction}}` - KEV reduction (customer - chainguard)
- `{{images_with_customer_kevs}}` - Number of customer images containing KEVs
- `{{images_with_chainguard_kevs}}` - Number of Chainguard images containing KEVs

**Example usage in markdown:**
```markdown
### Security Assessment for {{customer_name}}

Analysis of {{images_scanned}} images found a {{reduction_percentage}} reduction in vulnerabilities.
Current images contain {{total_customer_vulns}} CVEs, while Chainguard equivalents reduce this to {{total_chainguard_vulns}}.

**Critical finding**: {{images_with_customer_kevs}} images contain {{total_customer_kevs}} actively exploited vulnerabilities (KEVs).
```

See `sample-exec-summary.md` and `sample-appendix.md` for complete examples.

### Cost Analysis Options (XLSX)

| Option | Default | Description |
|--------|---------|-------------|
| `--hours-per-vuln` | 3.0 | Average hours to remediate one CVE |
| `--hourly-rate` | 100.0 | Engineering hourly rate in USD |
| `--with-fips` | - | Include FIPS cost analysis (auto-detects FIPS images) |

### CHPS Integration

| Option | Default | Description |
|--------|---------|-------------|
| `--with-chps` | - | Include CHPS (Container Hardening and Provenance Scanner) scoring |

### KEV Integration

| Option | Default | Description |
|--------|---------|-------------|
| `--with-kevs` | - | Check CVEs against CISA's Known Exploited Vulnerabilities catalog and highlight them in reports |

### Convenience Options

| Option | Default | Description |
|--------|---------|-------------|
| `--with-all` | - | Enable all optional features (equivalent to `--with-chps --with-fips --with-kevs`) |

### Pricing Configuration

The pricing quote feature automatically generates subscription cost estimates based on the Chainguard images in your assessment. It classifies images by tier (base, application, fips, ai) and applies volume-based pricing with bulk discounts.

#### Prerequisites

1. **Pricing Policy File**: Create or customize `pricing-policy.yaml` from the example:
   ```bash
   cp example-pricing-policy.yaml pricing-policy.yaml
   # Edit pricing-policy.yaml to match your pricing structure
   ```

2. **GitHub Authentication** (for automatic image tier classification):

   Gauge needs access to the private `chainguard-images/images-private` repository to classify images by tier. Choose one of these authentication methods:

   **Option 1: GitHub CLI (Recommended)**
   ```bash
   # Install gh CLI if not already installed
   brew install gh  # macOS
   # or: https://cli.github.com/

   # Authenticate
   gh auth login
   ```
   Gauge will automatically use the `gh` CLI token.

   **Option 2: Environment Variable**
   ```bash
   export GITHUB_TOKEN="your_personal_access_token"
   ```
   Create a Personal Access Token at: https://github.com/settings/tokens

   Required scopes: `repo` (for private repository access)

#### Image Tier Classification

Gauge automatically classifies Chainguard images into pricing tiers:

- **base** - Minimal OS and language runtimes (python, node, golang-base, etc.)
- **application** - Full applications, databases, web servers (nginx, postgres, redis, etc.)
- **fips** - FIPS 140-2/140-3 validated images (python-fips, nginx-fips, etc.)
- **ai** - Machine learning and AI framework images (pytorch, tensorflow, etc.)

The classification:
1. Checks local tier mappings in `config/image_tiers.yaml` (cached from previous runs)
2. Fetches unknown images from GitHub metadata
3. Auto-saves new classifications for team sharing
4. Prompts to commit updated `image_tiers.yaml` to version control

#### Pricing Policy Format

The pricing policy YAML file defines tier-based pricing with volume discounts:

```yaml
# Base images pricing
base:
  - min: 1
    max: 10
    list_price: 29000  # $290.00 list price per image (prices in cents)
    discount_percent: 0  # No discount
  - min: 11
    max: 25
    list_price: 29000  # $290.00 list price
    discount_percent: 10  # 10% discount = $261.00 final price
  - min: 26
    max: null  # null = unlimited
    list_price: 29000  # $290.00 list price
    discount_percent: 20  # 20% discount = $232.00 final price

# Application images pricing
application:
  - min: 1
    max: 10
    list_price: 35000  # $350.00 list price per image
    discount_percent: 0
  # ... additional ranges

# Metadata
policy_name: "Standard Enterprise Pricing"
effective_date: "2025-01-01"
currency: "USD"
pricing_unit: "per image per year"
notes: |
  - All prices are annual subscription fees
  - Volume discounts apply within each tier independently
  - Contact sales@chainguard.dev for custom pricing
```

**Pricing Calculation:**
- `list_price`: The list price per image (before any discounts)
- `discount_percent`: Discount percentage as a float (e.g., `10` for 10%, `20.5` for 20.5%)
- **Discounted price is automatically calculated**: `list_price * (1 - discount_percent/100)`
- Example: `list_price: 29000` with `discount_percent: 10` yields final price of $261.00

See `example-pricing-policy.yaml` for a complete example with all four tiers.

#### Usage Examples

```bash
# Generate only pricing quote
gauge --input images.csv --customer "Acme Corp" --output pricing

# Generate pricing + cost analysis
gauge --output pricing,cost_analysis

# Use custom pricing policy
gauge --pricing-policy custom-pricing.yaml --output pricing

# Generate default outputs (vuln_summary + cost_analysis)
gauge --input images.csv --customer "Acme Corp"

# Generate all three output types
gauge --input images.csv --customer "Acme Corp" --output vuln_summary,cost_analysis,pricing
```

#### Output

The pricing quote generator creates a professional HTML report (`{customer}_pricing_quote.html`) containing:
- Customer name and quote date
- Policy name and effective date
- Line items by tier with quantities, prices, and specific image names
- Volume discounts automatically applied
- Subtotal and grand total
- Policy notes and contact information

Images are listed under their respective tiers, making it easy to see which specific images are included in each pricing tier.

### Cache Options

| Option | Default | Description |
|--------|---------|-------------|
| `--cache-dir` | `.cache` | Cache directory |
| `--no-cache` | - | Disable caching |
| `--clear-cache` | - | Clear cache before starting |
| `--no-fresh-check` | - | Skip checking for fresh images |
| `--resume` | - | Resume from previous checkpoint (if available) |
| `--checkpoint-file` | `.gauge_checkpoint.json` | Checkpoint file path for resume functionality |

## Caching System

Gauge includes two complementary performance systems:

### Intelligent Caching
- **Digest-based**: Uses image SHA256 digests as cache keys
- **Exact flag matching**: Cache validated against CHPS/KEV/FIPS flags (e.g., running without `--with-chps` invalidates cache entries that have CHPS data)
- **Automatic freshness**: Only pulls when remote digest differs
- **Platform-aware**: Different cache per platform (linux/amd64, linux/arm64, etc.)
- **Portable**: Cache can be shared between machines

### Checkpoint/Resume
- **Automatic**: Progress saved after each image pair scan
- **Interruptible**: Safe to stop with Ctrl+C - no work lost
- **Resumable**: Continue from where you left off with `--resume`
- **Smart**: Only scans remaining pairs on resume

### Benefits
- **Significant speedup**: Cached scans return instantly
- **Reliable**: Digest-based validation ensures accuracy
- **Resilient**: Interrupted scans can be resumed
- **Efficient**: Perfect for scanning large fleets (50+ images)

### Cache Management

```bash
# View cache statistics (automatic in logs)
# Cache: 15 hits, 5 misses (75.0% hit rate)

# Clear cache before run
gauge --clear-cache

# Disable caching
gauge --no-cache

# Custom cache location
gauge --cache-dir /path/to/cache

# Resume from checkpoint
gauge --resume

# Custom checkpoint file
gauge --checkpoint-file /path/to/checkpoint.json
```

## Performance

### Optimization Features
- **Parallel scanning**: Multiple images scanned simultaneously
- **Intelligent caching**: Digest-based cache eliminates redundant scans
- **Efficient SBOM usage**: Syft SBOM reused for Grype scanning
- **Auto-tuned workers**: Defaults to optimal thread count

### Typical Performance
- First scan: ~30-60 seconds per image pair
- Cached scan: < 1 second per image pair
- With 4 workers: 3-5x faster than sequential

## Examples

### Basic Vulnerability Assessment Summary

Generate a simple assessment summary report:

```bash
gauge --input my-images.csv \
      --output vuln_summary \
      --output-dir ./reports \
      --customer "Acme Corporation"
```

This generates `./reports/acme_corporation.html`.

### Full Cost Analysis with FIPS

Generate a comprehensive cost analysis with ROI and FIPS calculations:

```bash
gauge --input production-images.csv \
      --output cost_analysis \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --hours-per-vuln 4 \
      --hourly-rate 125 \
      --with-fips \
      --max-workers 8
```

This generates `./reports/acme_corp.xlsx` with FIPS cost analysis.

### Generate Both Outputs

Generate both assessment summary and cost analysis in one scan:

```bash
gauge --input my-images.csv \
      --output both \
      --output-dir ./reports \
      --customer "Acme Corp" \
      --exec-summary summary.md \
      --hours-per-vuln 4 \
      --hourly-rate 125
```

This generates both `./reports/acme_corp.html` and `./reports/acme_corp.xlsx`.

### High-Performance Scan

Maximize scanning speed for large fleets:

```bash
gauge --input large-fleet.csv \
      --output vuln_summary \
      --output-dir ./reports \
      --customer "Large Fleet" \
      --max-workers 12 \
      --no-fresh-check  # Skip freshness checks for speed
```

This generates `./reports/large_fleet.html`.

### Resume Interrupted Scan

For long-running scans that may be interrupted, use checkpoint/resume functionality:

```bash
# Start a long scan (creates checkpoint automatically)
gauge --input large-fleet.csv \
      --output both \
      --output-dir ./reports \
      --customer "Fleet Analysis" \
      --resume

# If interrupted (Ctrl+C), you'll see:
# Scan interrupted! Partial results saved to checkpoint.
# Run with --resume to continue from: .gauge_checkpoint.json

# Resume from where you left off
gauge --input large-fleet.csv \
      --output both \
      --output-dir ./reports \
      --customer "Fleet Analysis" \
      --resume

# Output:
# Resuming from checkpoint: .gauge_checkpoint.json
# Loaded 15 previous scan results
# Scanning 10 remaining pairs...
```

**Benefits:**
- Automatically saves progress after each image pair
- Resume skips already-scanned images
- Safe to interrupt with Ctrl+C - no lost work
- Useful for scanning 50+ image pairs

## Troubleshooting

### Common Issues

**"Neither docker nor podman found"**
- Ensure Docker or Podman is installed and in PATH
- Test with `docker --version` or `podman --version`

**"syft is required but not found"**
- Install Syft following prerequisites above
- Test with `syft version`

**"grype is required but not found"**
- Install Grype following prerequisites above
- Test with `grype version`

**Slow scanning**
- Use `--cache-dir` to enable caching
- Increase `--max-workers` for more parallelism
- Use `--no-fresh-check` to skip image freshness validation

**Cache issues**
- Clear cache with `--clear-cache`
- Disable caching with `--no-cache`
- Check cache directory permissions

**Checkpoint/Resume issues**
- Delete stale checkpoint: `rm .gauge_checkpoint.json`
- Use different checkpoint file: `--checkpoint-file custom.json`
- Checkpoint is JSON - safe to inspect/edit manually
- Resume only works with same CSV file and image pairs

**Container authentication errors (cgr.dev/chainguard-private)**
- Ensure you've run `chainctl auth login` and `chainctl auth configure-docker` on the host
- Mount both Docker config and chainctl config:
  ```bash
  docker run --rm \
    -v $(pwd):/workspace \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v ~/.docker:/root/.docker:ro \
    -v ~/.config/chainctl:/root/.config/chainctl:ro \
    gauge:latest --input /workspace/images.csv
  ```
- Rebuild the container image if needed (it includes `chainctl` for the credential helper)
- Verify host authentication works: `docker pull cgr.dev/chainguard-private/python:latest`
- Check chainctl auth status: `chainctl auth status`

## Project Structure

```
gauge/
├── src/                    # Source code (core, integrations, outputs, utils)
├── tests/                  # Unit and integration tests (188 tests)
├── config/                 # Configuration files
├── resources/              # Static assets (logos, images)
├── example-images.csv      # Sample input file
├── sample-exec-summary.md  # Example template
├── sample-appendix.md      # Example template
├── example-pricing-policy.yaml  # Pricing policy example
├── requirements.txt        # Python dependencies
├── setup.py                # Package configuration
├── Dockerfile              # Container build
├── README.md               # User documentation (this file)
├── CONTRIBUTING.md         # Developer documentation
└── MIGRATION.md            # Legacy tool migration guide
```

For detailed architecture, module organization, and development guidelines, see **[CONTRIBUTING.md](CONTRIBUTING.md)**.

## Development

### Running Without Install

```bash
# Using PYTHONPATH
PYTHONPATH=src python -m cli --help

# Or use the development script
python -m src.cli --help
```

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_models.py

# Run with verbose output
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=src --cov-report=term-missing

# Run only unit tests (fast)
pytest tests/ -m unit

# Type checking (if mypy installed)
mypy src/

# Code formatting (if black installed)
black src/
```

## Migration from Legacy Tools

If you're migrating from `cg_assessment` or `minibva`, see **[MIGRATION.md](MIGRATION.md)** for detailed instructions.

**Quick migration:**
- `python -m gauge` → `gauge`
- `python3 minibva.py` → `gauge`
- All features preserved, much simpler commands!

## Contributing

Contributions are welcome! For detailed information on:
- Development setup and environment
- Project architecture and design principles
- Code organization and module responsibilities
- Testing guidelines and procedures
- Code style and documentation standards
- Common development tasks
- Pull request process

Please see **[CONTRIBUTING.md](CONTRIBUTING.md)**.

### Quick Start for Contributors

```bash
# Clone and setup
git clone <repository-url>
cd gauge
pip install -r requirements.txt
pip install -e .

# Run tests
pytest

# See CONTRIBUTING.md for detailed guidelines
```

## License

Copyright © 2025 Chainguard. All Rights Reserved.

---

**Built with [Claude Code](https://claude.com/claude-code)**
