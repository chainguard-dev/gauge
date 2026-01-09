"""
LLM-powered fuzzy image matching for Chainguard equivalents.

Implements Tier 4 matching using Claude API for complex image name transformations
that can't be handled by heuristics alone.
"""

import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import anthropic

from constants import CLI_SUBPROCESS_TIMEOUT, DEFAULT_LLM_CONFIDENCE
from integrations.github_metadata import GitHubMetadataClient
from utils.llm_utils import db_connection, parse_json_response

logger = logging.getLogger(__name__)


@dataclass
class LLMMatchResult:
    """Result of an LLM matching attempt."""

    chainguard_image: Optional[str]
    """Matched Chainguard image reference"""

    confidence: float
    """Confidence score (0.0 - 1.0)"""

    reasoning: str
    """LLM's reasoning for the match"""

    cached: bool = False
    """Whether result was from cache"""

    latency_ms: float = 0.0
    """API call latency in milliseconds"""


class LLMMatcher:
    """
    LLM-powered image matcher using Claude API.

    Uses Claude to perform fuzzy matching for complex image name patterns
    that can't be handled by rule-based heuristics.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-5",
        cache_dir: Optional[Path] = None,
        github_token: Optional[str] = None,
        confidence_threshold: float = DEFAULT_LLM_CONFIDENCE,
    ):
        """
        Initialize LLM matcher.

        Args:
            api_key: Anthropic API key (falls back to ANTHROPIC_API_KEY env var)
            model: Claude model to use (default: claude-sonnet-4-5)
            cache_dir: Directory for SQLite cache (default: ~/.cache/gauge)
            github_token: GitHub token for fetching available images
            confidence_threshold: Minimum confidence to consider a match (default: {DEFAULT_LLM_CONFIDENCE})
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self.confidence_threshold = confidence_threshold

        if not self.api_key:
            logger.warning(
                "No Anthropic API key found. LLM matching will be disabled. "
                "To enable, either:\n"
                "  1. Set ANTHROPIC_API_KEY environment variable\n"
                "  2. Pass api_key to constructor\n"
                "  3. Use --anthropic-api-key flag"
            )
            self.client = None
        else:
            self.client = anthropic.Anthropic(api_key=self.api_key)

        # Initialize cache
        self.cache_dir = cache_dir or Path.home() / ".cache" / "gauge"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_db = self.cache_dir / "llm_cache.db"
        self._init_cache_db()

        # Initialize GitHub metadata client for available images
        self.github_metadata = GitHubMetadataClient(github_token=github_token)

        # Load full Chainguard catalog at initialization
        self.chainguard_catalog = self._load_full_catalog()
        if self.chainguard_catalog:
            logger.info(f"Loaded {len(self.chainguard_catalog)} images from Chainguard catalog")
        else:
            logger.warning("Failed to load Chainguard catalog - LLM matching may be limited")

        # Telemetry
        self.telemetry_file = self.cache_dir / "llm_telemetry.jsonl"

    def _init_cache_db(self) -> None:
        """Initialize SQLite cache database."""
        with db_connection(self.cache_db) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_cache (
                    image_name TEXT PRIMARY KEY,
                    model TEXT,
                    chainguard_image TEXT,
                    confidence REAL,
                    reasoning TEXT,
                    timestamp INTEGER
                )
            """
            )
            conn.commit()

    def _get_cached_result(self, image_name: str) -> Optional[LLMMatchResult]:
        """
        Get cached result for image.

        Args:
            image_name: Image name to look up

        Returns:
            Cached result if available, None otherwise
        """
        with db_connection(self.cache_db) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT chainguard_image, confidence, reasoning
                FROM llm_cache
                WHERE image_name = ? AND model = ?
            """,
                (image_name, self.model),
            )
            row = cursor.fetchone()

        if row:
            logger.debug(f"Cache hit for {image_name}")
            return LLMMatchResult(
                chainguard_image=row[0],
                confidence=row[1],
                reasoning=row[2],
                cached=True,
            )

        return None

    def _cache_result(
        self,
        image_name: str,
        chainguard_image: Optional[str],
        confidence: float,
        reasoning: str,
    ) -> None:
        """
        Cache LLM result.

        Args:
            image_name: Source image name
            chainguard_image: Matched Chainguard image (or None)
            confidence: Confidence score
            reasoning: LLM reasoning
        """
        with db_connection(self.cache_db) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO llm_cache
                (image_name, model, chainguard_image, confidence, reasoning, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (image_name, self.model, chainguard_image, confidence, reasoning, int(time.time())),
            )
            conn.commit()

    def _log_telemetry(
        self,
        image_name: str,
        result: LLMMatchResult,
        success: bool,
    ) -> None:
        """
        Log telemetry data for LLM matching.

        Args:
            image_name: Source image name
            result: Match result
            success: Whether a match was found above threshold
        """
        telemetry = {
            "timestamp": int(time.time()),
            "image_name": image_name,
            "model": self.model,
            "chainguard_image": result.chainguard_image,
            "confidence": result.confidence,
            "success": success,
            "cached": result.cached,
            "latency_ms": result.latency_ms,
        }

        with open(self.telemetry_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(telemetry) + "\n")

    # Cache TTL for catalog: 1 hour
    CATALOG_CACHE_TTL_SECONDS = 3600

    def _load_full_catalog(self, org: str = "chainguard-private") -> list[str]:
        """
        Load the full Chainguard image catalog at initialization.

        Args:
            org: Chainguard organization (default: chainguard-private)

        Returns:
            List of all available image names
        """
        # Check cache first
        catalog_cache_file = self.cache_dir / f"chainguard_catalog_{org}.json"
        if catalog_cache_file.exists():
            try:
                with open(catalog_cache_file, "r", encoding="utf-8") as f:
                    cache_data = json.load(f)
                cache_time = cache_data.get("timestamp", 0)
                if time.time() - cache_time < self.CATALOG_CACHE_TTL_SECONDS:
                    images = cache_data.get("images", [])
                    logger.debug(f"Using cached catalog ({len(images)} images, age: {time.time() - cache_time:.0f}s)")
                    return images
            except (json.JSONDecodeError, OSError) as e:
                logger.debug(f"Failed to load catalog cache: {e}")

        if not shutil.which("chainctl"):
            logger.debug("chainctl not available for catalog loading")
            return []

        try:
            result = subprocess.run(
                ["chainctl", "img", "repos", "list", "--parent", org, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=CLI_SUBPROCESS_TIMEOUT,
            )

            if result.returncode != 0:
                logger.warning(f"chainctl img repos list failed: {result.stderr}")
                return []

            repos_data = json.loads(result.stdout)
            items = repos_data.get("items", [])
            all_images = sorted([item.get("name", "") for item in items if item.get("name")])

            # Cache the catalog
            try:
                cache_data = {"timestamp": time.time(), "images": all_images}
                with open(catalog_cache_file, "w", encoding="utf-8") as f:
                    json.dump(cache_data, f)
                logger.debug(f"Cached {len(all_images)} images to {catalog_cache_file}")
            except OSError as e:
                logger.debug(f"Failed to cache catalog: {e}")

            return all_images

        except subprocess.TimeoutExpired:
            logger.warning("chainctl catalog loading timed out")
            return []
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse chainctl output: {e}")
            return []
        except Exception as e:
            logger.warning(f"chainctl catalog loading failed: {e}")
            return []

    def _web_search_image_context(self, image_name: str) -> str:
        """
        Search the web to understand what a source image does.

        Args:
            image_name: The source image name to research

        Returns:
            Context string describing what the image does
        """
        if not self.client:
            return ""

        # Extract the core image name for searching
        search_name = image_name
        if "/" in search_name:
            search_name = search_name.split("/")[-1]
        if ":" in search_name:
            search_name = search_name.split(":")[0]

        try:
            # Use Claude with web search to understand what this image does
            logger.debug(f"LLM web search for context on '{search_name}'")
            response = self.client.messages.create(
                model=self.model,
                max_tokens=500,
                messages=[
                    {
                        "role": "user",
                        "content": f"""Research what the container image "{image_name}" does.

Search the web to find information about this image - its purpose, what software it contains, and what problem it solves.

Provide a concise summary (2-3 sentences) of:
1. What this software/tool does
2. Its primary use case
3. Any alternative names or related projects

If you cannot find information, say "Unknown image".""",
                    }
                ],
            )
            return response.content[0].text.strip()
        except Exception as e:
            logger.debug(f"Web search for {image_name} failed: {e}")
            return ""

    def _generate_hyphen_variations(self, name: str) -> list[str]:
        """
        Generate hyphen variations for concatenated names.

        Examples:
            argoexec → ['argo-exec']
            registryphoton → ['registry-photon']
            deviceplugin → ['device-plugin']

        Args:
            name: Image name to generate variations for

        Returns:
            List of hyphenated variations
        """
        variations = []

        # Skip if already has hyphens/underscores
        if "-" in name or "_" in name:
            return variations

        # Common word boundaries to try splitting on
        # These are common suffixes/prefixes in container image names
        split_words = [
            "exec", "cli", "operator", "controller", "manager", "server",
            "client", "proxy", "agent", "plugin", "exporter", "registry",
            "photon", "base", "runtime", "sdk", "api", "web", "ui",
            "db", "cache", "queue", "worker", "scheduler", "webhook",
        ]

        name_lower = name.lower()
        for word in split_words:
            # Try splitting at this word boundary
            if word in name_lower and name_lower != word:
                idx = name_lower.find(word)
                if idx > 0:
                    # Split: "argoexec" → "argo-exec"
                    before = name[:idx]
                    after = name[idx:]
                    hyphenated = f"{before}-{after}".lower()
                    if hyphenated not in variations:
                        variations.append(hyphenated)

        return variations

    def _generate_search_terms(self, base_name: str, org_name: Optional[str] = None) -> list[str]:
        """
        Generate search terms for finding Chainguard image candidates.

        Creates multiple variations of the image name to increase chances
        of finding matches in the catalog.

        Args:
            base_name: Base image name (without registry/tag)
            org_name: Organization name if available

        Returns:
            List of search terms to try
        """
        search_terms = [base_name]

        # Add hyphen variations for concatenated names (argoexec → argo-exec)
        hyphenated = self._generate_hyphen_variations(base_name)
        search_terms.extend(hyphenated)

        # Add individual words from the base name as search terms
        words = re.split(r"[-_]+", base_name)
        if len(words) > 1:
            # Add the most significant words (usually not generic ones)
            generic_words = ("manager", "controller", "server", "client", "k8s", "kubernetes")
            significant_words = [w for w in words if w.lower() not in generic_words]
            if significant_words:
                search_terms.append(" ".join(significant_words[:2]))
                # Also add individual significant words for broader search
                for word in significant_words[:2]:
                    if len(word) > 3:
                        search_terms.append(word)

        # Add org name as search term (argoproj → argo)
        if org_name:
            # Strip common suffixes like "proj", "io", "dev"
            org_base = re.sub(r"(proj|io|dev|oss|images)$", "", org_name.lower())
            if org_base and len(org_base) > 2:
                search_terms.append(org_base)
                # Also try org-base combination (e.g., "argo exec" for argoproj/argoexec)
                search_terms.append(f"{org_base} {base_name}")

        # Add common prefix substitutions for k8s images
        if "k8s" in base_name.lower():
            # k8s-device-plugin → device-plugin, nvidia-device-plugin
            without_k8s = re.sub(r"k8s[-_]?", "", base_name, flags=re.IGNORECASE)
            if without_k8s:
                search_terms.append(without_k8s)
                search_terms.append(f"nvidia {without_k8s}")

        return search_terms

    def _search_chainguard_images(self, search_term: str) -> list[str]:
        """
        Search for available Chainguard images in the pre-loaded catalog.

        Args:
            search_term: Term to fuzzy search for

        Returns:
            List of matching image names
        """
        if not self.chainguard_catalog:
            logger.debug("No catalog available for image search")
            return []

        # Fuzzy filter using search term
        # Split search term into parts for flexible matching
        search_parts = re.split(r"[-_\s]+", search_term.lower())
        # Also create a normalized version without hyphens for matching
        search_normalized = re.sub(r"[-_\s]+", "", search_term.lower())

        matching_images = []
        for image in self.chainguard_catalog:
            image_lower = image.lower()
            image_normalized = re.sub(r"[-_]+", "", image_lower)

            # Method 1: All search parts appear in the image name
            if all(part in image_lower for part in search_parts if len(part) > 2):
                matching_images.append(image)
            # Method 2: Normalized search matches normalized image (handles hyphen variations)
            # e.g., "argoexec" matches "argo-exec" → both normalize to "argoexec"
            elif search_normalized in image_normalized or image_normalized in search_normalized:
                matching_images.append(image)
            # Method 3: Any significant search part matches (broader search)
            elif any(part in image_lower for part in search_parts if len(part) > 4):
                matching_images.append(image)

        # Sort by relevance (prefer exact normalized matches, then shorter names)
        def relevance_score(img):
            img_normalized = re.sub(r"[-_]+", "", img.lower())
            # Exact normalized match gets highest priority
            if search_normalized == img_normalized:
                return (0, len(img))
            # Normalized substring match
            if search_normalized in img_normalized:
                return (1, len(img))
            # Regular match
            return (2, len(img))

        matching_images.sort(key=relevance_score)

        logger.debug(f"Found {len(matching_images)} Chainguard images matching '{search_term}': {matching_images[:10]}")
        return matching_images[:20]  # Limit to top 20 matches

    def _match_against_catalog(self, image_name: str, context: str = "") -> LLMMatchResult:
        """
        Match source image against the full Chainguard catalog.

        Args:
            image_name: Source image to match
            context: Optional additional context about the source image

        Returns:
            LLMMatchResult with match and metadata
        """
        if not self.client:
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning="LLM client not available",
            )

        if not self.chainguard_catalog:
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning="Chainguard catalog not available",
            )

        start_time = time.time()
        prompt = self._build_catalog_prompt(image_name, context=context)

        try:
            logger.debug(f"LLM catalog matching for '{image_name}' (model: {self.model})")
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )

            latency_ms = (time.time() - start_time) * 1000
            response_text = parse_json_response(message.content[0].text)
            response = json.loads(response_text)

            # Validate the suggested image is in the catalog
            suggested = response.get("chainguard_image")
            if suggested:
                # Extract just the image name
                img_name = suggested
                if "/" in img_name:
                    img_name = img_name.split("/")[-1]
                if ":" in img_name:
                    img_name = img_name.split(":")[0]

                if img_name not in self.chainguard_catalog:
                    logger.warning(f"LLM suggested '{img_name}' which is not in catalog - rejecting")
                    return LLMMatchResult(
                        chainguard_image=None,
                        confidence=0.0,
                        reasoning=f"Suggested image '{img_name}' not in catalog",
                        latency_ms=latency_ms,
                    )

            return LLMMatchResult(
                chainguard_image=response.get("chainguard_image"),
                confidence=response.get("confidence", 0.0),
                reasoning=response.get("reasoning", ""),
                latency_ms=latency_ms,
            )

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"JSON parse error: {e}",
            )
        except Exception as e:
            logger.warning(f"Catalog matching failed: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"Error: {e}",
            )

    def _iterative_refinement(self, image_name: str) -> LLMMatchResult:
        """
        Iterative refinement for hard-to-match images.

        Uses multiple search strategies to gather more context and find matches.

        Args:
            image_name: Source image to match

        Returns:
            LLMMatchResult with match and metadata
        """
        if not self.client:
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning="LLM client not available",
            )

        # Try to understand the image through a more detailed search
        prompt = f"""I need to find a Chainguard equivalent for the container image: {image_name}

Please help me understand:
1. What is this software/tool? What does it do?
2. What is the upstream project or organization?
3. Are there any alternative names or related projects?
4. What category does this fall into (database, web server, CI/CD tool, monitoring, etc.)?

Search the web if needed to find accurate information. Be concise."""

        try:
            logger.debug(f"LLM iterative refinement research for '{image_name}'")
            response = self.client.messages.create(
                model=self.model,
                max_tokens=500,
                messages=[{"role": "user", "content": prompt}],
            )
            detailed_context = response.content[0].text.strip()

            # Now try matching with this detailed context
            if detailed_context:
                return self._match_against_catalog(image_name, context=detailed_context)

        except Exception as e:
            logger.debug(f"Iterative refinement failed: {e}")

        return LLMMatchResult(
            chainguard_image=None,
            confidence=0.0,
            reasoning="No match found after iterative refinement",
        )

    def _build_catalog_prompt(self, image_name: str, context: str = "") -> str:
        """
        Build matching prompt with full catalog for Claude.

        Args:
            image_name: Image name to match
            context: Optional additional context about the source image

        Returns:
            Formatted prompt string
        """
        # Format catalog as a list
        if self.chainguard_catalog:
            catalog_str = "\n".join(f"  - {img}" for img in self.chainguard_catalog)
        else:
            catalog_str = "  (catalog not available)"

        context_section = ""
        if context:
            context_section = f"""
**Additional context about the source image:**
{context}
"""

        prompt = f"""You are an expert at matching container images to their Chainguard equivalents.

**Image to match:** {image_name}
{context_section}
**Available Chainguard images (complete catalog):**
{catalog_str}

**Your task:**
1. Understand what software/tool the source image provides
2. Find the best matching image from the catalog above
3. Only select an image if you're confident it provides the same or equivalent functionality

**Key matching principles:**
- Base OS images (debian, ubuntu, alpine, centos, rhel) → chainguard-base
- Look for functional equivalents, not just name matches
- Bitnami images often map to "-iamguarded" variants
- FIPS variants end with "-fips"
- Some images have different names (e.g., postgres-exporter → prometheus-postgres-exporter)

**Output Format (JSON):**
{{
  "chainguard_image": "cgr.dev/chainguard-private/IMAGE:latest",
  "confidence": 0.85,
  "reasoning": "Brief explanation of the match"
}}

**Confidence Scoring:**
- 0.9+: Direct equivalent (same software, same purpose)
- 0.8-0.89: Strong functional match
- 0.7-0.79: Reasonable match with some uncertainty
- Below 0.7: Return null

If no suitable match exists in the catalog, return:
{{
  "chainguard_image": null,
  "confidence": 0.0,
  "reasoning": "Why no match exists"
}}

**CRITICAL:** You MUST select from the catalog above. Do not invent image names.

Respond with ONLY the JSON output."""

        return prompt

    def _enhanced_match(self, image_name: str) -> LLMMatchResult:
        """
        Enhanced matching using web search and chainctl to find the best match.

        This method is called as a fallback when the simple LLM match fails.
        It uses Claude's tool use to:
        1. Search the web for the upstream project
        2. Search available Chainguard images via chainctl
        3. Reason about the best match

        Args:
            image_name: Source image to match

        Returns:
            LLMMatchResult with match and metadata
        """
        if not self.client:
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning="LLM matching disabled (no API key)",
            )

        start_time = time.time()

        # Extract base name and org for searching
        base_name = image_name
        org_name = None
        if "/" in base_name:
            parts = base_name.split("/")
            if len(parts) >= 2:
                org_name = parts[-2]  # e.g., "argoproj" from "argoproj/argoexec"
            base_name = parts[-1]
        if ":" in base_name:
            base_name = base_name.split(":")[0]

        # Search for candidate Chainguard images using generated search terms
        search_terms = self._generate_search_terms(base_name, org_name)
        candidate_images = set()
        for term in search_terms:
            candidates = self._search_chainguard_images(term)
            candidate_images.update(candidates)

        candidate_list = sorted(candidate_images)[:30]  # Limit to 30 candidates

        logger.info(f"Enhanced matching for '{image_name}' with {len(candidate_list)} candidates")

        # Build enhanced prompt with candidate list
        candidates_str = "\n".join(f"  - {img}" for img in candidate_list) if candidate_list else "  (no candidates found via chainctl)"

        enhanced_prompt = f"""You are an expert at matching container images to their Chainguard equivalents.

**Image to match:** {image_name}

**CRITICAL CONTEXT**: The simple match suggested an image that does NOT exist in the Chainguard registry.
You MUST choose from the available images below, or return null if none match.

**Available Chainguard images (verified via chainctl):**
{candidates_str}

**Your task:**
1. Analyze the source image path and name to understand what software this is
2. Use your knowledge about this software's upstream project and common naming conventions
3. Match it to one of the available Chainguard images above

**Key insights:**
- mcr.microsoft.com/oss/kubernetes/* images are often Kubernetes cloud provider components
- The upstream project for Azure Kubernetes components is typically kubernetes-sigs/cloud-provider-azure
- Chainguard often uses the upstream project name (e.g., "cloud-provider-azure-*" rather than "azure-cloud-*")
- registry.k8s.io/provider-*/* images map to cloud-provider-* in Chainguard

**Output Format (JSON):**
{{
  "chainguard_image": "cgr.dev/chainguard-private/IMAGE:latest",
  "confidence": 0.85,
  "reasoning": "Brief explanation of why this match makes sense based on the upstream project"
}}

If no available image matches (confidence < 0.7), return:
{{
  "chainguard_image": null,
  "confidence": 0.0,
  "reasoning": "Explanation of why no match was possible"
}}

IMPORTANT: You MUST choose from the available images list above. Do NOT suggest images that aren't in the list.

Respond with ONLY the JSON output, no additional text."""

        try:
            logger.debug(f"LLM enhanced matching for '{image_name}' with {len(candidate_list)} candidates")
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[{"role": "user", "content": enhanced_prompt}],
            )

            latency_ms = (time.time() - start_time) * 1000

            # Extract text response
            response_text = message.content[0].text.strip() if message.content else None

            if not response_text:
                logger.warning("Enhanced match returned no text response")
                return LLMMatchResult(
                    chainguard_image=None,
                    confidence=0.0,
                    reasoning="No response from enhanced matching",
                    latency_ms=latency_ms,
                )

            # Parse JSON from response, handling markdown code blocks
            response_text = parse_json_response(response_text)
            response = json.loads(response_text)

            result = LLMMatchResult(
                chainguard_image=response.get("chainguard_image"),
                confidence=response.get("confidence", 0.0),
                reasoning=response.get("reasoning", ""),
                cached=False,
                latency_ms=latency_ms,
            )

            # Cache the result (with a marker that it was from enhanced matching)
            self._cache_result(
                image_name,
                result.chainguard_image,
                result.confidence,
                f"[enhanced] {result.reasoning}",
            )

            logger.info(
                f"Enhanced match for {image_name}: {result.chainguard_image} "
                f"(confidence: {result.confidence:.0%}, latency: {latency_ms:.0f}ms)"
            )

            return result

        except anthropic.APIError as e:
            logger.error(f"Anthropic API error in enhanced matching: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"API error: {e}",
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse enhanced match response as JSON: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"JSON parse error: {e}",
            )
        except Exception as e:
            logger.error(f"Enhanced matching error: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"Error: {e}",
            )

    def match(self, image_name: str) -> LLMMatchResult:
        """
        Find Chainguard image match using LLM with full catalog.

        Uses a 3-tier matching approach:
        1. Match against full catalog with LLM understanding
        2. If no match, use web search to understand the source image better
        3. If still no match, iterative refinement with additional context

        Args:
            image_name: Source image to match

        Returns:
            LLMMatchResult with match and metadata
        """
        # Check if LLM matching is available
        if not self.client:
            logger.debug("LLM matching disabled (no API key)")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning="LLM matching disabled (no API key)",
            )

        # Check cache first
        cached_result = self._get_cached_result(image_name)
        if cached_result:
            self._log_telemetry(
                image_name, cached_result, cached_result.confidence >= self.confidence_threshold
            )
            return cached_result

        start_time = time.time()
        try:
            # TIER 1: Match against full catalog
            result = self._match_against_catalog(image_name)

            if result.confidence >= self.confidence_threshold:
                logger.info(
                    f"Catalog match for {image_name}: {result.chainguard_image} "
                    f"(confidence: {result.confidence:.0%})"
                )
                self._cache_result(image_name, result.chainguard_image, result.confidence, result.reasoning)
                self._log_telemetry(image_name, result, True)
                return result

            # TIER 2: Web search to understand the source image
            logger.info(f"No direct match for {image_name}, searching for context...")
            context = self._web_search_image_context(image_name)

            if context and context != "Unknown image":
                logger.debug(f"Found context for {image_name}: {context[:100]}...")
                result = self._match_against_catalog(image_name, context=context)

                if result.confidence >= self.confidence_threshold:
                    logger.info(
                        f"Context-enhanced match for {image_name}: {result.chainguard_image} "
                        f"(confidence: {result.confidence:.0%})"
                    )
                    result = LLMMatchResult(
                        chainguard_image=result.chainguard_image,
                        confidence=result.confidence,
                        reasoning=f"[web-search] {result.reasoning}",
                        cached=False,
                        latency_ms=(time.time() - start_time) * 1000,
                    )
                    self._cache_result(image_name, result.chainguard_image, result.confidence, result.reasoning)
                    self._log_telemetry(image_name, result, True)
                    return result

            # TIER 3: Iterative refinement - try broader search
            logger.info(f"No match with context for {image_name}, trying iterative refinement...")
            result = self._iterative_refinement(image_name)

            latency_ms = (time.time() - start_time) * 1000
            result = LLMMatchResult(
                chainguard_image=result.chainguard_image,
                confidence=result.confidence,
                reasoning=result.reasoning,
                cached=False,
                latency_ms=latency_ms,
            )

            # Cache and log final result
            self._cache_result(image_name, result.chainguard_image, result.confidence, result.reasoning)
            success = result.confidence >= self.confidence_threshold
            self._log_telemetry(image_name, result, success)

            return result

        except anthropic.APIError as e:
            logger.error(f"Anthropic API error: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"API error: {e}",
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response as JSON: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"JSON parse error: {e}",
            )

        except Exception as e:
            logger.error(f"LLM matching error: {e}")
            return LLMMatchResult(
                chainguard_image=None,
                confidence=0.0,
                reasoning=f"Error: {e}",
            )
