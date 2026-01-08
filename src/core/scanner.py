"""
Core vulnerability scanning engine.

Orchestrates image scanning using Syft (for SBOM) and Grype (for vulnerabilities),
with intelligent caching and parallel execution support.
"""

import json
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timezone
from typing import Optional

from constants import (
    DEFAULT_MAX_WORKERS,
    DEFAULT_PLATFORM,
    VERSION_CHECK_TIMEOUT,
    SYFT_TIMEOUT,
    GRYPE_TIMEOUT,
)
from core.cache import ScanCache
from core.models import (
    ImageAnalysis,
    ImagePair,
    ScanResult,
    SeverityLevel,
    VulnerabilityCount,
)
from core.retry_queue import RetryQueue
from utils.docker_utils import DockerClient
from utils.chps_utils import CHPSScanner

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """
    Vulnerability scanner using Syft and Grype.

    Provides intelligent caching, parallel scanning, and comprehensive
    error handling for production use.
    """

    def __init__(
        self,
        cache: ScanCache,
        docker_client: DockerClient,
        max_workers: int = DEFAULT_MAX_WORKERS,
        platform: Optional[str] = DEFAULT_PLATFORM,
        check_fresh_images: bool = True,
        with_chps: bool = False,
        chps_max_workers: int = 2,
        kev_catalog: Optional['KEVCatalog'] = None,
    ):
        """
        Initialize vulnerability scanner.

        Args:
            cache: Scan cache instance
            docker_client: Docker/Podman client
            max_workers: Maximum parallel scanning threads
            platform: Platform specification for scans (e.g., "linux/amd64")
            check_fresh_images: Whether to ensure images are up-to-date
            with_chps: Whether to include CHPS scoring
            chps_max_workers: Maximum parallel CHPS scanning threads
            kev_catalog: KEV catalog for checking known exploited vulnerabilities
        """
        self.cache = cache
        self.docker = docker_client
        self.max_workers = max_workers
        self.platform = platform
        self.check_fresh_images = check_fresh_images
        self.with_chps = with_chps
        self.chps_max_workers = chps_max_workers
        self.kev_catalog = kev_catalog
        self.retry_queue = RetryQueue()

        if with_chps:
            logger.info("CHPS scoring enabled, initializing CHPS scanner...")
            self.chps_scanner = CHPSScanner(docker_client.runtime)
            if self.chps_scanner.chps_available:
                logger.info("CHPS scanner initialized successfully")
            else:
                logger.warning("CHPS scanner initialized but CHPS image not available")
        else:
            logger.debug("CHPS scoring disabled")
            self.chps_scanner = None

        self._verify_tools()

    def _verify_tools(self) -> None:
        """Verify required scanning tools are available."""
        for tool in ["syft", "grype"]:
            try:
                result = subprocess.run(
                    [tool, "version"],
                    capture_output=True,
                    timeout=VERSION_CHECK_TIMEOUT
                )
                if result.returncode != 0:
                    raise RuntimeError(f"{tool} not found or not working")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                raise RuntimeError(f"{tool} is required but not found in PATH")

        logger.info("Scanner tools verified: syft, grype")

    def scan_image(
        self,
        image: str,
        context: Optional[str] = None,
        pair_index: Optional[int] = None,
        upstream_image: Optional[str] = None
    ) -> ImageAnalysis:
        """
        Scan a single image for vulnerabilities.

        Args:
            image: Image reference to scan
            context: Context string for retry tracking (e.g., 'alternative', 'chainguard')
            pair_index: Index of the image pair being scanned (for retry tracking)
            upstream_image: Optional upstream image to try as fallback if pull fails

        Returns:
            ImageAnalysis with scan results

        Raises:
            RuntimeError: If image cannot be pulled or scan fails
        """
        original_image = image
        used_fallback = False
        pull_successful = True

        # Check if we should update the image first
        if self.check_fresh_images:
            image, used_fallback, pull_successful, error_type = self.docker.ensure_fresh_image(image, self.platform, upstream_image=upstream_image)
            if used_fallback:
                logger.warning(
                    f"Using {image} as fallback for {original_image}"
                )
            if not pull_successful:
                error_msg = f"Failed to pull image {original_image} and all fallback strategies failed"

                # Add to retry queue for later retry attempt
                if context:
                    self.retry_queue.add(
                        image=original_image,
                        platform=self.platform,
                        error_message=error_msg,
                        error_type=error_type,
                        context=context,
                        pair_index=pair_index
                    )
                    # Use WARNING since retry queue will attempt again
                    logger.warning(f"Failed to pull image {original_image} - queued for retry")
                else:
                    # No retry possible, log as ERROR
                    logger.error(f"Failed to pull image {original_image} - cannot scan")

                raise RuntimeError(error_msg)

        # Get image digest for caching
        digest = self.docker.get_image_digest(image)

        # Check cache (with KEV requirements if enabled)
        require_kevs = self.kev_catalog is not None
        cached = self.cache.get(image, digest, require_kevs=require_kevs)
        if cached:
            logger.info(f"✓ {image} (cached)")
            # If we used fallback, update the cached result to reflect that
            if used_fallback:
                cached = replace(
                    cached,
                    used_latest_fallback=True,
                    original_image=original_image,
                )
            return cached

        # Perform fresh scan
        logger.info(f"🔍 Scanning {image}")

        try:
            # Get image size
            size_mb = self.docker.get_image_size_mb(image)

            # Run Syft to generate SBOM
            package_count, sbom_json = self._run_syft(image)

            # Run Grype on SBOM to get vulnerabilities
            vulnerabilities, cve_ids = self._run_grype_on_sbom(sbom_json, image)

            # Check for KEVs if catalog is available
            kev_cves = []
            if self.kev_catalog and cve_ids:
                for cve_id in cve_ids:
                    if self.kev_catalog.is_kev(cve_id):
                        kev_cves.append(cve_id)

                if kev_cves:
                    logger.info(f"⚠️  {len(kev_cves)} Known Exploited Vulnerabilities found in {image}")

            # Create analysis result (CHPS score will be added later)
            analysis = ImageAnalysis(
                name=image,
                size_mb=size_mb,
                package_count=package_count,
                vulnerabilities=vulnerabilities,
                scan_timestamp=datetime.now(timezone.utc),
                digest=digest,
                cache_hit=False,
                used_latest_fallback=used_fallback,
                original_image=original_image if used_fallback else None,
                kev_count=len(kev_cves),
                kev_cves=kev_cves,
            )

            # Cache the result
            self.cache.put(analysis)

            kev_info = f", KEVs:{len(kev_cves)}" if kev_cves else ""
            logger.info(
                f"✓ {image} - {vulnerabilities.total} CVEs "
                f"(C:{vulnerabilities.critical} H:{vulnerabilities.high} "
                f"M:{vulnerabilities.medium}{kev_info})"
            )

            return analysis

        except Exception as e:
            logger.error(f"Failed to scan {image}: {e}")
            raise

    def _run_syft(self, image: str) -> tuple[int, str]:
        """
        Run Syft to generate SBOM.

        Args:
            image: Image to scan

        Returns:
            Tuple of (package_count, sbom_json_string)

        Raises:
            RuntimeError: If syft command fails
        """
        # Note: We don't pass --platform to Syft because we've already pulled
        # the correct platform-specific image using ensure_fresh_image().
        # Syft will scan whatever local image is available.
        cmd = ["syft", image, "-o", "json"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SYFT_TIMEOUT,
                check=True
            )

            syft_data = json.loads(result.stdout)
            package_count = len(syft_data.get("artifacts", []))

            return package_count, result.stdout

        except subprocess.CalledProcessError as e:
            # Capture and include stderr in error message for better debugging
            error_msg = f"Syft command failed with exit code {e.returncode}"
            if e.stderr:
                error_msg += f"\nStderr: {e.stderr.strip()}"
            if e.stdout:
                error_msg += f"\nStdout: {e.stdout.strip()}"
            raise RuntimeError(error_msg) from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"Syft scan timed out after {SYFT_TIMEOUT} seconds") from e

    def _run_grype_on_sbom(self, sbom_json: str, image_name: str) -> tuple[VulnerabilityCount, list[str]]:
        """
        Run Grype on SBOM to detect vulnerabilities.

        Args:
            sbom_json: SBOM in JSON format from Syft
            image_name: Image name (for logging)

        Returns:
            Tuple of (VulnerabilityCount, list of CVE IDs)

        Raises:
            RuntimeError: If grype command fails
        """
        try:
            result = subprocess.run(
                ["grype", "-o", "json"],
                input=sbom_json,
                capture_output=True,
                text=True,
                timeout=GRYPE_TIMEOUT,
                check=True
            )

            grype_data = json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            # Capture and include stderr in error message for better debugging
            error_msg = f"Grype command failed with exit code {e.returncode}"
            if e.stderr:
                error_msg += f"\nStderr: {e.stderr.strip()}"
            if e.stdout:
                error_msg += f"\nStdout: {e.stdout.strip()}"
            raise RuntimeError(error_msg) from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"Grype scan timed out after 300 seconds") from e

        # Count vulnerabilities by severity and collect CVE IDs
        counts = {
            SeverityLevel.CRITICAL.value: 0,
            SeverityLevel.HIGH.value: 0,
            SeverityLevel.MEDIUM.value: 0,
            SeverityLevel.LOW.value: 0,
            SeverityLevel.NEGLIGIBLE.value: 0,
        }
        cve_ids = []

        for match in grype_data.get("matches", []):
            severity = match["vulnerability"]["severity"]
            if severity in counts:
                counts[severity] += 1
            else:
                # Unknown or Negligible go into negligible bucket
                counts[SeverityLevel.NEGLIGIBLE.value] += 1

            # Collect CVE ID
            cve_id = match.get("vulnerability", {}).get("id")
            if cve_id and cve_id.startswith("CVE-"):
                cve_ids.append(cve_id)

        total = sum(counts.values())

        vuln_count = VulnerabilityCount(
            total=total,
            critical=counts[SeverityLevel.CRITICAL.value],
            high=counts[SeverityLevel.HIGH.value],
            medium=counts[SeverityLevel.MEDIUM.value],
            low=counts[SeverityLevel.LOW.value],
            negligible=counts[SeverityLevel.NEGLIGIBLE.value],
        )

        return vuln_count, cve_ids


    def scan_image_pair(
        self,
        pair: ImagePair,
        pair_index: Optional[int] = None
    ) -> ScanResult:
        """
        Scan both images in a pair concurrently.

        Args:
            pair: ImagePair to scan
            pair_index: Index of this pair in the batch (for retry tracking)

        Returns:
            ScanResult with both analyses
        """
        logger.info(f"Scanning pair: {pair}")

        try:
            # Scan both images concurrently within the pair for better performance
            with ThreadPoolExecutor(max_workers=2) as executor:
                # Submit both scans
                # Pass upstream_image for alternative (if available) to enable upstream fallback
                alt_future = executor.submit(
                    self.scan_image,
                    pair.alternative_image,
                    context="alternative",
                    pair_index=pair_index,
                    upstream_image=pair.upstream_image
                )
                cg_future = executor.submit(
                    self.scan_image,
                    pair.chainguard_image,
                    context="chainguard",
                    pair_index=pair_index
                )

                # Wait for both to complete and collect results
                alternative_analysis = alt_future.result()
                chainguard_analysis = cg_future.result()

            return ScanResult(
                pair=pair,
                alternative_analysis=alternative_analysis,
                chainguard_analysis=chainguard_analysis,
                scan_successful=True,
            )

        except Exception as e:
            logger.error(f"Failed to scan pair {pair}: {e}")
            # Attempt to get partial results if one scan succeeded
            alt_result = None
            cg_result = None

            try:
                if 'alt_future' in locals():
                    alt_result = alt_future.result(timeout=0)
            except:
                pass

            try:
                if 'cg_future' in locals():
                    cg_result = cg_future.result(timeout=0)
            except:
                pass

            return ScanResult(
                pair=pair,
                alternative_analysis=alt_result,
                chainguard_analysis=cg_result,
                scan_successful=False,
                error_message=str(e),
            )

    def scan_image_pairs_parallel(
        self, pairs: list[ImagePair]
    ) -> list[ScanResult]:
        """
        Scan multiple image pairs in parallel.

        Args:
            pairs: List of image pairs to scan

        Returns:
            List of scan results
        """
        logger.info(f"Scanning {len(pairs)} image pairs with {self.max_workers} workers")

        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_pair = {
                executor.submit(self.scan_image_pair, pair, i): (pair, i)
                for i, pair in enumerate(pairs)
            }

            for i, future in enumerate(as_completed(future_to_pair), 1):
                pair, pair_index = future_to_pair[future]
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"Progress: {i}/{len(pairs)} pairs completed")
                except Exception as e:
                    logger.error(f"Exception scanning {pair}: {e}")
                    results.append(
                        ScanResult(
                            pair=pair,
                            alternative_analysis=None,
                            chainguard_analysis=None,
                            scan_successful=False,
                            error_message=str(e),
                        )
                    )

        # Log summary
        successful_scans = [r for r in results if r.scan_successful]
        failed_scans = [r for r in results if not r.scan_successful]
        logger.info(f"Initial scan complete: {len(successful_scans)} succeeded, {len(failed_scans)} failed")

        # Run CHPS scans in parallel if enabled
        if self.with_chps and self.chps_scanner and self.chps_scanner.chps_available and successful_scans:
            results = self._run_chps_scans_parallel(results)

        # Process retry queue if there are failed pulls
        if not self.retry_queue.is_empty():
            logger.info(f"Processing {self.retry_queue.size()} failed image pulls for retry...")
            results = self._process_retry_queue(results, pairs)

        # Display failure classification summary
        self._display_failure_summary()

        return results

    def _run_chps_scans_parallel(self, results: list[ScanResult]) -> list[ScanResult]:
        """Run CHPS scans in parallel for all successful scans."""
        logger.info(f"Running CHPS scans for {len(results) * 2} images with {self.chps_max_workers} workers...")
        
        # Collect all unique images to scan
        images_to_scan = {}
        for r in results:
            if r.alternative_analysis:
                images_to_scan[r.alternative_analysis.name] = r.alternative_analysis
            if r.chainguard_analysis:
                images_to_scan[r.chainguard_analysis.name] = r.chainguard_analysis
        
        chps_scores = {}
        with ThreadPoolExecutor(max_workers=self.chps_max_workers) as executor:
            future_to_image = {
                executor.submit(self.chps_scanner.scan_image, image_name): image_name
                for image_name in images_to_scan
            }
            for future in as_completed(future_to_image):
                image_name = future_to_image[future]
                try:
                    score = future.result()
                    if score:
                        chps_scores[image_name] = score
                except Exception as e:
                    logger.warning(f"CHPS scan for {image_name} failed: {e}")
        
        # Update results with CHPS scores
        updated_results = []
        for r in results:
            new_alt_analysis = r.alternative_analysis
            if r.alternative_analysis and r.alternative_analysis.name in chps_scores:
                new_alt_analysis = replace(
                    r.alternative_analysis,
                    chps_score=chps_scores[r.alternative_analysis.name]
                )
            
            new_cg_analysis = r.chainguard_analysis
            if r.chainguard_analysis and r.chainguard_analysis.name in chps_scores:
                new_cg_analysis = replace(
                    r.chainguard_analysis,
                    chps_score=chps_scores[r.chainguard_analysis.name]
                )
            
            updated_results.append(replace(
                r,
                alternative_analysis=new_alt_analysis,
                chainguard_analysis=new_cg_analysis,
            ))
            
        return updated_results

    def _display_failure_summary(self) -> None:
        """Display categorized summary of all failures."""
        failed_pulls = self.retry_queue.get_all()

        if not failed_pulls:
            return

        # Categorize failures by error type
        categories: dict[str, list[str]] = {
            "auth": [],
            "timeout": [],
            "rate_limit": [],
            "not_found": [],
            "unknown": []
        }

        for failed_pull in failed_pulls:
            error_type = failed_pull.error_type
            categories.setdefault(error_type, []).append(failed_pull.image)

        # Build categorized summary message
        summary_parts = []

        if categories.get("auth"):
            images = categories["auth"]
            # Extract unique registries from auth-failed images
            registries = set()
            for img in images:
                registry = self.docker._extract_registry_from_image(img)
                registries.add(registry)

            registry_list = "\n    ".join(sorted(registries))
            summary_parts.append(
                f"Authentication required ({len(images)} images):\n"
                f"  Registries:\n    {registry_list}\n"
                f"  → Run: docker login <registry>"
            )

        if categories.get("timeout"):
            count = len(categories["timeout"])
            summary_parts.append(
                f"Timed out after 120s ({count} images):\n"
                f"  → Try: --max-workers 1 (reduce concurrency)\n"
                f"  → Or check network/Docker daemon performance"
            )

        if categories.get("rate_limit"):
            count = len(categories["rate_limit"])
            summary_parts.append(
                f"Rate limited ({count} images):\n"
                f"  → Wait a few minutes and retry\n"
                f"  → Using mirror.gcr.io fallback for Docker Hub images"
            )

        if categories.get("not_found"):
            count = len(categories["not_found"])
            summary_parts.append(
                f"Not found after all fallbacks ({count} images):\n"
                f"  → Verify image names and tags\n"
                f"  → Check if images exist in registry"
            )

        if categories.get("unknown"):
            count = len(categories["unknown"])
            summary_parts.append(f"Unknown errors ({count} images)")

        if summary_parts:
            summary = "\n\n".join(summary_parts)
            logger.warning(f"\nFailure Summary:\n{summary}")

    def _process_retry_queue(
        self,
        results: list[ScanResult],
        pairs: list[ImagePair]
    ) -> list[ScanResult]:
        """
        Process retry queue and update results for successful retries.

        Args:
            results: Original scan results
            pairs: Original list of image pairs

        Returns:
            Updated scan results with successful retries incorporated
        """
        failed_pulls = self.retry_queue.get_all()
        retry_successes = []
        retry_failures = []
        skipped_permanent_failures = []

        for failed_pull in failed_pulls:
            # Skip retrying permanent failures
            if failed_pull.error_type in ("auth", "not_found"):
                logger.debug(
                    f"Skipping retry for {failed_pull.image} - permanent failure "
                    f"(error_type: {failed_pull.error_type})"
                )
                skipped_permanent_failures.append(failed_pull)
                continue

            logger.info(f"Retrying pull for {failed_pull.image} ({failed_pull.context})...")

            # Attempt to pull the image again
            image, used_fallback, pull_successful, error_type = self.docker.pull_image_with_fallback(
                failed_pull.image,
                failed_pull.platform
            )

            if pull_successful:
                retry_successes.append(failed_pull)
                # Remove from queue so it doesn't appear in failure summary
                self.retry_queue.remove(failed_pull)
                logger.info(f"✓ Retry successful for {failed_pull.image}")

                # If pull succeeded, try to scan the image
                try:
                    analysis = self.scan_image(image)

                    # Update the corresponding result
                    if failed_pull.pair_index is not None:
                        pair = pairs[failed_pull.pair_index]
                        result_idx = next(
                            (i for i, r in enumerate(results) if r.pair == pair),
                            None
                        )

                        if result_idx is not None:
                            result = results[result_idx]

                            # Update the appropriate analysis field
                            if failed_pull.context == "alternative":
                                results[result_idx] = replace(
                                    result,
                                    alternative_analysis=analysis,
                                    scan_successful=result.chainguard_analysis is not None,
                                    error_message=None if result.chainguard_analysis else result.error_message
                                )
                            elif failed_pull.context == "chainguard":
                                results[result_idx] = replace(
                                    result,
                                    chainguard_analysis=analysis,
                                    scan_successful=result.alternative_analysis is not None,
                                    error_message=None if result.alternative_analysis else result.error_message
                                )

                            logger.info(f"Updated result for pair {failed_pull.pair_index}")

                except Exception as e:
                    logger.error(f"Retry scan failed for {failed_pull.image}: {e}")
                    retry_failures.append(failed_pull)
            else:
                retry_failures.append(failed_pull)
                logger.warning(f"✗ Retry failed for {failed_pull.image}")

        # Log retry summary
        if retry_successes or retry_failures or skipped_permanent_failures:
            logger.info(
                f"Retry complete: {len(retry_successes)} succeeded, "
                f"{len(retry_failures)} failed, "
                f"{len(skipped_permanent_failures)} skipped (permanent failures)"
            )

            if retry_successes:
                success_list = "\n".join(f"  - {fp.image} ({fp.context})" for fp in retry_successes)
                logger.info(f"Successfully retried images:\n{success_list}")

            if retry_failures:
                failure_list = "\n".join(f"  - {fp.image} ({fp.context})" for fp in retry_failures)
                logger.warning(f"Failed retry attempts:\n{failure_list}")

            if skipped_permanent_failures:
                skipped_list = "\n".join(
                    f"  - {fp.image} ({fp.context}) - {fp.error_type}"
                    for fp in skipped_permanent_failures
                )
                logger.info(f"Skipped permanent failures (not retried):\n{skipped_list}")

        return results
