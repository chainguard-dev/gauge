"""
Match command for automatically finding Chainguard image equivalents.

Implements the `gauge match` command for batch matching of alternative images
to their Chainguard equivalents.
"""

import csv
import logging
import sys
from pathlib import Path
from typing import Optional

from utils.image_matcher import ImageMatcher, MatchResult
from utils.issue_matcher import IssueMatchResult, search_github_issues_for_images
from utils.registry_access import RegistryAccessChecker
from utils.upstream_finder import UpstreamImageFinder

logger = logging.getLogger(__name__)


def match_images(
    input_file: Path,
    output_file: Path,
    min_confidence: float = 0.7,
    interactive: bool = False,
    dfc_mappings_file: Optional[Path] = None,
    cache_dir: Optional[Path] = None,
    find_upstream: bool = False,
    upstream_confidence: float = 0.7,
    upstream_mappings_file: Optional[Path] = None,
    enable_llm_matching: bool = True,
    llm_model: str = "claude-sonnet-4-5",
    llm_confidence_threshold: float = 0.7,
    anthropic_api_key: Optional[str] = None,
    generate_dfc_pr: bool = False,
    github_token: Optional[str] = None,
    known_registries: Optional[list[str]] = None,
) -> tuple[list[tuple[str, MatchResult]], list[str]]:
    """
    Match alternative images to Chainguard equivalents.

    Args:
        input_file: Input file with alternative images (one per line or CSV)
        output_file: Output CSV file with matched pairs
        min_confidence: Minimum confidence threshold (0.0 - 1.0)
        interactive: Enable interactive mode for low-confidence matches
        dfc_mappings_file: Optional local DFC mappings file
        cache_dir: Cache directory for DFC mappings
        find_upstream: Enable upstream image discovery as fallback for inaccessible registries
        upstream_confidence: Minimum confidence for upstream matches (0.0 - 1.0)
        upstream_mappings_file: Optional manual upstream mappings file
        enable_llm_matching: Enable LLM-powered fuzzy matching (Tier 4)
        llm_model: Claude model to use for LLM matching
        llm_confidence_threshold: Minimum confidence for LLM matches (0.0 - 1.0)
        anthropic_api_key: Anthropic API key for LLM matching
        generate_dfc_pr: Generate DFC contribution files for high-confidence LLM matches
        github_token: GitHub token for issue search (required for issue matching)
        known_registries: Additional registries the user has credentials for

    Returns:
        Tuple of (matched_pairs with MatchResult, unmatched_images)
    """
    # Read input images
    logger.info(f"Reading images from {input_file}")
    alternative_images = read_input_file(input_file)
    logger.info(f"Found {len(alternative_images)} images to match")

    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Initialize registry access checker
    # This determines which registries are accessible (skip upstream discovery for those)
    registry_checker = RegistryAccessChecker(additional_registries=known_registries)
    if known_registries:
        logger.info(f"Added {len(known_registries)} known registries: {', '.join(known_registries)}")

    # Initialize upstream finder if enabled (used as fallback for inaccessible registries)
    upstream_finder = None
    if find_upstream:
        logger.info("Upstream discovery enabled (fallback for inaccessible registries)")
        upstream_finder = UpstreamImageFinder(
            manual_mappings_file=upstream_mappings_file,
            min_confidence=upstream_confidence,
        )

    # Initialize LLM matcher if enabled
    llm_matcher = None
    if enable_llm_matching:
        from utils.llm_matcher import LLMMatcher
        logger.info(f"LLM matching enabled (model: {llm_model}, threshold: {llm_confidence_threshold:.0%})")
        llm_matcher = LLMMatcher(
            api_key=anthropic_api_key,
            model=llm_model,
            cache_dir=cache_dir,
            confidence_threshold=llm_confidence_threshold,
        )
    else:
        logger.info("LLM matching disabled")

    # Initialize matcher
    logger.info("Initializing image matcher...")
    matcher = ImageMatcher(
        cache_dir=cache_dir,
        dfc_mappings_file=dfc_mappings_file,
        upstream_finder=upstream_finder,
        llm_matcher=llm_matcher,
        registry_checker=registry_checker,
    )

    # Initialize DFC contributor if requested
    dfc_contributor = None
    if generate_dfc_pr:
        from utils.dfc_contributor import DFCContributor
        # Put DFC contributions in the same directory as matched-log.csv
        dfc_contributor = DFCContributor(output_dir=output_file.parent)
        logger.info("DFC contribution generation enabled")


    # Match images
    matched_pairs: list[tuple[str, MatchResult]] = []
    unmatched_images: list[str] = []
    low_confidence_matches: list[tuple[str, MatchResult]] = []

    logger.info("Matching images...")
    for i, alt_image in enumerate(alternative_images, 1):
        result = matcher.match(alt_image)

        if result.chainguard_image is None:
            logger.warning(f"[{i}/{len(alternative_images)}] No match: {alt_image}")
            unmatched_images.append(alt_image)
        elif result.confidence >= min_confidence:
            # Show upstream info if available
            upstream_info = ""
            if result.upstream_image:
                upstream_info = f" (via upstream: {result.upstream_image}, {result.upstream_confidence:.0%})"

            # Show LLM reasoning if this was an LLM match
            llm_info = ""
            if result.method == "llm" and result.reasoning:
                llm_info = f"\n    LLM reasoning: {result.reasoning}"

            logger.info(
                f"[{i}/{len(alternative_images)}] ✓ Matched: {alt_image} → {result.chainguard_image} "
                f"(confidence: {result.confidence:.0%}, method: {result.method}){upstream_info}{llm_info}"
            )
            matched_pairs.append((alt_image, result))

            # Add to DFC contributor if heuristic or LLM match with high confidence
            # Skip DFC and manual matches as they're already in mappings
            if dfc_contributor and result.method in ["heuristic", "llm"]:
                dfc_contributor.add_match(alt_image, result)

        else:
            logger.warning(
                f"[{i}/{len(alternative_images)}] Low confidence: {alt_image} → {result.chainguard_image} "
                f"(confidence: {result.confidence:.0%})"
            )
            if interactive:
                low_confidence_matches.append((alt_image, result))
            else:
                unmatched_images.append(alt_image)

    # Handle interactive mode for low-confidence matches
    if interactive and low_confidence_matches:
        logger.info(f"\nReviewing {len(low_confidence_matches)} low-confidence matches...")
        for alt_image, result in low_confidence_matches:
            matched = handle_interactive_match(alt_image, result)
            if matched:
                # Convert tuple to MatchResult for consistency
                # Interactive mode returns (alt_image, chainguard_image) tuple
                # Wrap in a MatchResult with unknown confidence
                interactive_result = MatchResult(
                    chainguard_image=matched[1],
                    confidence=1.0,  # User accepted, so 100% confidence
                    method="interactive",
                    upstream_image=result.upstream_image,
                    upstream_confidence=result.upstream_confidence,
                    upstream_method=result.upstream_method,
                )
                matched_pairs.append((alt_image, interactive_result))
            else:
                unmatched_images.append(alt_image)

    # Write outputs
    logger.info(f"\nWriting detailed match log to {output_file}")
    write_matched_csv(output_file, matched_pairs)

    # Write intake file for gauge scan
    intake_file = output_file.parent / "matched-intake.csv"
    logger.info(f"Writing intake file for gauge scan to {intake_file}")
    write_matched_intake(intake_file, matched_pairs)

    # Search GitHub issues for unmatched images
    issue_matches: list[tuple[str, IssueMatchResult]] = []
    no_issue_matches: list[str] = []

    if unmatched_images:
        try:
            issue_matches, no_issue_matches = search_github_issues_for_images(
                unmatched_images=unmatched_images,
                anthropic_api_key=anthropic_api_key,
                llm_model=llm_model,
                cache_dir=cache_dir,
                confidence_threshold=llm_confidence_threshold,
                github_token=github_token,
            )

            # Output table of successful issue matches
            if issue_matches:
                logger.info("\n" + "=" * 80)
                logger.info("Existing GitHub Issues Found for Unmatched Images:")
                logger.info("=" * 80)
                for image, result in issue_matches:
                    logger.info(f"  {image}")
                    logger.info(f"    Issue: {result.matched_issue.title}")
                    logger.info(f"    URL: {result.matched_issue.url}")
                    logger.info(f"    Confidence: {result.confidence:.0%}")
                logger.info("=" * 80)

            # Output list of images with no matching issues
            if no_issue_matches:
                logger.info(f"\nNo matching issues found for {len(no_issue_matches)} images:")
                for image in no_issue_matches:
                    logger.info(f"  - {image}")

            # Write unmatched file with issue search results
            unmatched_file = output_file.parent / "unmatched.txt"
            write_unmatched_file(unmatched_file, issue_matches, no_issue_matches)
            logger.info(f"\nUnmatched images written to {unmatched_file}")

        except ValueError as e:
            logger.error(f"GitHub authentication required for issue search: {e}")
            sys.exit(1)

    # Generate DFC contribution files if requested
    if dfc_contributor and dfc_contributor.suggestions:
        logger.info(f"\nGenerating DFC contribution files...")
        dfc_files = dfc_contributor.generate_all()
        if dfc_files:
            logger.info("DFC contribution files generated:")
            for file_type, file_path in dfc_files.items():
                logger.info(f"  - {file_type}: {file_path}")

            # Count by method
            method_counts = {}
            for _, _, result in dfc_contributor.suggestions:
                method_counts[result.method] = method_counts.get(result.method, 0) + 1

            logger.info(f"\nIncluded {len(dfc_contributor.suggestions)} high-confidence matches:")
            for method, count in sorted(method_counts.items()):
                logger.info(f"  - {method}: {count}")

            logger.info("\nTo contribute these mappings to DFC:")
            logger.info("  1. Review the suggested mappings in dfc-suggestions.yaml")
            logger.info("  2. Fork the DFC repository: https://github.com/chainguard-dev/dfc")
            if 'patch' in dfc_files:
                logger.info(f"  3. Apply the patch: patch -p0 < {dfc_files['patch'].name}")
            logger.info("  4. Create a pull request with your changes")
    elif dfc_contributor:
        logger.info("\nNo high-confidence matches to contribute to DFC (need confidence >= 0.85)")

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info(f"Matching complete:")
    logger.info(f"  Matched: {len(matched_pairs)}")
    logger.info(f"  Unmatched: {len(unmatched_images)}")
    logger.info(f"  Match rate: {len(matched_pairs) / len(alternative_images) * 100:.1f}%")

    # Show method breakdown
    method_counts = {}
    for _, result in matched_pairs:
        method_counts[result.method] = method_counts.get(result.method, 0) + 1

    if method_counts:
        logger.info(f"\nMatch method breakdown:")
        for method, count in sorted(method_counts.items()):
            logger.info(f"  {method}: {count} ({count / len(matched_pairs) * 100:.1f}%)")

    # Display successful matches
    if matched_pairs:
        matches_list = "\n".join(
            f"  {alt_image} ⇒ {result.chainguard_image}"
            for alt_image, result in matched_pairs
        )
        logger.info(f"\nSuccessful matches:\n{matches_list}")

    logger.info("=" * 60)

    return matched_pairs, unmatched_images


def read_input_file(file_path: Path) -> list[str]:
    """
    Read alternative images from input file.

    Supports both text files (one image per line) and CSV files (first column).

    Args:
        file_path: Input file path

    Returns:
        List of alternative image references

    Raises:
        RuntimeError: If file cannot be read
    """
    images = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            # Try to detect if it's a CSV
            first_line = f.readline().strip()
            f.seek(0)

            if "," in first_line:
                # CSV file
                reader = csv.reader(f)
                # Skip header if present
                header = next(reader, None)
                if header and header[0].lower() in ["alternative_image", "image", "name"]:
                    pass  # Already skipped
                else:
                    # First line is data, add it
                    f.seek(0)
                    reader = csv.reader(f)

                for row in reader:
                    if row and row[0].strip():
                        # Skip comment lines (lines starting with #)
                        if row[0].strip().startswith('#'):
                            continue
                        images.append(row[0].strip())
            else:
                # Plain text file (or single-column CSV without commas)
                f.seek(0)
                lines = f.readlines()

                # Skip header if first line is a known header name
                start_idx = 0
                if lines and lines[0].strip().lower() in ["alternative_image", "image", "name"]:
                    start_idx = 1

                for line in lines[start_idx:]:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        images.append(line)

    except Exception as e:
        raise RuntimeError(f"Failed to read input file: {e}") from e

    if not images:
        raise RuntimeError("No images found in input file")

    return images


def write_matched_csv(file_path: Path, pairs: list[tuple[str, MatchResult]]) -> None:
    """Write matched image pairs to CSV file with full matching metadata."""
    with open(file_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "alternative_image",
            "upstream_image",
            "chainguard_image",
            "upstream_confidence",
            "match_confidence",
            "upstream_method",
            "match_method",
        ])
        for alt, result in pairs:
            writer.writerow([
                alt,
                result.upstream_image or "",
                result.chainguard_image,
                f"{result.upstream_confidence:.2f}" if result.upstream_confidence is not None else "",
                f"{result.confidence:.2f}",
                result.upstream_method or "",
                result.method,
            ])


def write_matched_intake(file_path: Path, pairs: list[tuple[str, MatchResult]]) -> None:
    """Write matched image pairs to 2-column CSV suitable for gauge scan intake."""
    with open(file_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["alternative_image", "chainguard_image"])
        for alt, result in pairs:
            writer.writerow([alt, result.chainguard_image])


def write_unmatched_file(
    file_path: Path,
    issue_matches: list[tuple[str, IssueMatchResult]],
    no_issue_matches: list[str],
) -> None:
    """
    Write unmatched images and their GitHub issue search results to a file.

    Args:
        file_path: Output file path
        issue_matches: List of (image, IssueMatchResult) for images with matching issues
        no_issue_matches: List of images with no matching issues
    """
    with open(file_path, "w", encoding="utf-8") as f:
        f.write("=" * 80 + "\n")
        f.write("UNMATCHED IMAGES - GitHub Issue Search Results\n")
        f.write("=" * 80 + "\n\n")

        # Write images with matching issues
        if issue_matches:
            f.write("EXISTING GITHUB ISSUES FOUND:\n")
            f.write("-" * 40 + "\n")
            for image, result in issue_matches:
                f.write(f"\n  Image: {image}\n")
                f.write(f"  Issue: {result.matched_issue.title}\n")
                f.write(f"  URL: {result.matched_issue.url}\n")
                f.write(f"  Confidence: {result.confidence:.0%}\n")
            f.write("\n")

        # Write images with no matching issues
        if no_issue_matches:
            f.write("NO MATCHING ISSUES FOUND:\n")
            f.write("-" * 40 + "\n")
            for image in no_issue_matches:
                f.write(f"  - {image}\n")
            f.write("\n")

        # Summary
        total = len(issue_matches) + len(no_issue_matches)
        f.write("=" * 80 + "\n")
        f.write(f"Summary: {len(issue_matches)} with existing issues, {len(no_issue_matches)} with no issues (total: {total})\n")
        f.write("=" * 80 + "\n")


def handle_interactive_match(alt_image: str, result: MatchResult) -> Optional[tuple[str, str]]:
    """
    Handle interactive matching for low-confidence results.

    Args:
        alt_image: Alternative image reference
        result: Match result with low confidence

    Returns:
        Matched pair if accepted, None if skipped
    """
    print(f"\nLow confidence match for: {alt_image}")
    print(f"  Suggested: {result.chainguard_image}")
    print(f"  Confidence: {result.confidence:.0%}")
    print(f"  Method: {result.method}")

    if result.alternatives:
        print("\n  Alternatives:")
        for i, alt in enumerate(result.alternatives[:5], 1):
            print(f"    {i}. {alt}")

    while True:
        choice = input("\nAccept (y), skip (n), or enter custom image: ").strip().lower()

        if choice == "y":
            return (alt_image, result.chainguard_image)
        elif choice == "n":
            return None
        elif choice.startswith("cgr.dev/"):
            # Custom Chainguard image provided
            return (alt_image, choice)
        elif choice.isdigit():
            # Selected alternative
            idx = int(choice) - 1
            if result.alternatives and 0 <= idx < len(result.alternatives):
                return (alt_image, result.alternatives[idx])
            else:
                print("Invalid selection. Try again.")
        else:
            print("Invalid input. Enter 'y', 'n', a number, or a custom image.")
