"""
Tests for the match command functionality.
"""

import csv
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from commands.match import (
    match_images,
    read_input_file,
    write_matched_csv,
    write_unmatched_file,
    handle_interactive_match,
)
from utils.image_matcher import MatchResult


class TestReadInputFile:
    """Test reading input files in various formats."""

    def test_read_text_file(self, tmp_path):
        """Test reading plain text file with one image per line."""
        input_file = tmp_path / "images.txt"
        input_file.write_text(
            "nginx:latest\n"
            "python:3.12\n"
            "golang:1.21\n"
        )

        images = read_input_file(input_file)

        assert len(images) == 3
        assert images[0] == "nginx:latest"
        assert images[1] == "python:3.12"
        assert images[2] == "golang:1.21"

    def test_read_text_file_with_comments(self, tmp_path):
        """Test reading text file with comments."""
        input_file = tmp_path / "images.txt"
        input_file.write_text(
            "# This is a comment\n"
            "nginx:latest\n"
            "# Another comment\n"
            "python:3.12\n"
        )

        images = read_input_file(input_file)

        assert len(images) == 2
        assert images[0] == "nginx:latest"
        assert images[1] == "python:3.12"

    def test_read_text_file_with_blank_lines(self, tmp_path):
        """Test reading text file with blank lines."""
        input_file = tmp_path / "images.txt"
        input_file.write_text(
            "nginx:latest\n"
            "\n"
            "python:3.12\n"
            "\n"
        )

        images = read_input_file(input_file)

        assert len(images) == 2
        assert images[0] == "nginx:latest"
        assert images[1] == "python:3.12"

    def test_read_csv_with_header(self, tmp_path):
        """Test reading CSV file with header."""
        input_file = tmp_path / "images.csv"
        # CSV needs commas to be detected as CSV
        with open(input_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["alternative_image"])
            writer.writerow(["nginx:latest"])
            writer.writerow(["python:3.12"])

        images = read_input_file(input_file)

        assert len(images) == 2
        assert images[0] == "nginx:latest"
        assert images[1] == "python:3.12"

    def test_read_csv_without_header(self, tmp_path):
        """Test reading CSV file without header."""
        input_file = tmp_path / "images.csv"
        input_file.write_text(
            "nginx:latest,some_other_col\n"
            "python:3.12,another_value\n"
        )

        images = read_input_file(input_file)

        assert len(images) == 2
        assert images[0] == "nginx:latest"
        assert images[1] == "python:3.12"

    def test_read_csv_with_image_header(self, tmp_path):
        """Test reading CSV file with 'image' header variant."""
        input_file = tmp_path / "images.csv"
        # CSV needs commas to be detected as CSV
        with open(input_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["image"])
            writer.writerow(["nginx:latest"])

        images = read_input_file(input_file)

        assert len(images) == 1
        assert images[0] == "nginx:latest"

    def test_read_empty_file(self, tmp_path):
        """Test reading empty file raises error."""
        input_file = tmp_path / "empty.txt"
        input_file.write_text("")

        with pytest.raises(RuntimeError, match="No images found"):
            read_input_file(input_file)

    def test_read_nonexistent_file(self, tmp_path):
        """Test reading nonexistent file raises error."""
        input_file = tmp_path / "nonexistent.txt"

        with pytest.raises(RuntimeError, match="Failed to read input file"):
            read_input_file(input_file)


class TestWriteOutputFiles:
    """Test writing output files."""

    def test_write_matched_csv(self, tmp_path):
        """Test writing matched pairs to CSV."""
        from utils.image_matcher import MatchResult

        output_file = tmp_path / "matched.csv"
        pairs = [
            ("nginx:latest", MatchResult(
                chainguard_image="cgr.dev/chainguard/nginx-fips:latest",
                confidence=0.95,
                method="dfc",
            )),
            ("python:3.12", MatchResult(
                chainguard_image="cgr.dev/chainguard/python:latest",
                confidence=0.85,
                method="heuristic",
            )),
        ]

        write_matched_csv(output_file, pairs)

        # Verify file contents
        with open(output_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) == 3  # Header + 2 data rows
        assert rows[0] == ["alternative_image", "upstream_image", "chainguard_image",
                          "upstream_confidence", "match_confidence", "upstream_method", "match_method"]
        assert rows[1][0] == "nginx:latest"
        assert rows[1][2] == "cgr.dev/chainguard/nginx-fips:latest"
        assert rows[2][0] == "python:3.12"
        assert rows[2][2] == "cgr.dev/chainguard/python:latest"

    def test_write_empty_matched_csv(self, tmp_path):
        """Test writing empty matched pairs CSV."""
        output_file = tmp_path / "matched.csv"
        pairs = []

        write_matched_csv(output_file, pairs)

        # Verify only header exists
        with open(output_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert rows[0] == ["alternative_image", "upstream_image", "chainguard_image",
                          "upstream_confidence", "match_confidence", "upstream_method", "match_method"]

    def test_write_unmatched_file(self, tmp_path):
        """Test writing unmatched images with issue search results to text file."""
        from integrations.github_issue_search import GitHubIssue
        from utils.issue_matcher import IssueMatchResult

        output_file = tmp_path / "unmatched.txt"

        # Create mock issue match result
        mock_issue = GitHubIssue(
            number=123,
            title="Request: custom-app",
            body="Please add custom-app",
            url="https://github.com/chainguard-dev/image-requests/issues/123",
            labels=["image-request"],
            state="open",
            created_at="2024-01-01T00:00:00Z",
        )
        issue_match_result = IssueMatchResult(
            image_name="custom-app:v1.0",
            matched_issue=mock_issue,
            confidence=0.95,
            reasoning="Direct match",
        )

        issue_matches = [("custom-app:v1.0", issue_match_result)]
        no_issue_matches = ["internal-tool:latest"]

        write_unmatched_file(output_file, issue_matches, no_issue_matches)

        # Verify file contents
        content = output_file.read_text()

        assert "UNMATCHED IMAGES" in content
        assert "EXISTING GITHUB ISSUES FOUND" in content
        assert "custom-app:v1.0" in content
        assert "Request: custom-app" in content
        assert "https://github.com/chainguard-dev/image-requests/issues/123" in content
        assert "NO MATCHING ISSUES FOUND" in content
        assert "internal-tool:latest" in content
        assert "Summary: 1 with existing issues, 1 with no issues (total: 2)" in content


class TestMatchImages:
    """Test the main match_images function."""

    @pytest.fixture
    def mock_dfc_yaml(self):
        """Mock DFC mappings YAML content."""
        return """
images:
  nginx: nginx-fips:latest
  python*: python
  golang*: go
"""

    @patch('commands.match.ImageMatcher')
    def test_match_images_all_matched(self, mock_matcher_class, tmp_path, mock_dfc_yaml):
        """Test matching when all images match successfully."""
        # Setup input
        input_file = tmp_path / "input.txt"
        input_file.write_text("nginx:latest\npython:3.12\n")

        output_file = tmp_path / "matched.csv"
        unmatched_file = tmp_path / "unmatched.txt"

        # Mock matcher
        mock_matcher = MagicMock()
        mock_matcher_class.return_value = mock_matcher

        # Mock match results
        mock_matcher.match.side_effect = [
            MatchResult(
                chainguard_image="cgr.dev/chainguard/nginx-fips:latest",
                confidence=0.95,
                method="dfc"
            ),
            MatchResult(
                chainguard_image="cgr.dev/chainguard/python:latest",
                confidence=0.95,
                method="dfc"
            ),
        ]

        # Run matching
        with patch('commands.match.search_github_issues_for_images') as mock_search:
            mock_search.return_value = ([], [])  # No issue matches
            matched, unmatched = match_images(
                input_file=input_file,
                output_file=output_file,
                min_confidence=0.7,
                github_token="test-token",
            )

        # Verify results
        assert len(matched) == 2
        assert len(unmatched) == 0
        assert output_file.exists()

    @patch('commands.match.ImageMatcher')
    def test_match_images_with_unmatched(self, mock_matcher_class, tmp_path):
        """Test matching with some unmatched images."""
        # Setup input
        input_file = tmp_path / "input.txt"
        input_file.write_text("nginx:latest\ncustom-app:v1.0\n")

        output_file = tmp_path / "matched.csv"

        # Mock matcher
        mock_matcher = MagicMock()
        mock_matcher_class.return_value = mock_matcher

        # Mock match results
        mock_matcher.match.side_effect = [
            MatchResult(
                chainguard_image="cgr.dev/chainguard/nginx-fips:latest",
                confidence=0.95,
                method="dfc"
            ),
            MatchResult(
                chainguard_image=None,
                confidence=0.0,
                method="none"
            ),
        ]

        # Run matching
        with patch('commands.match.search_github_issues_for_images') as mock_search:
            mock_search.return_value = ([], ["custom-app:v1.0"])  # No issue matches
            matched, unmatched = match_images(
                input_file=input_file,
                output_file=output_file,
                min_confidence=0.7,
                github_token="test-token",
            )

        # Verify results
        assert len(matched) == 1
        assert len(unmatched) == 1
        assert unmatched[0] == "custom-app:v1.0"
        assert output_file.exists()

    @patch('commands.match.ImageMatcher')
    def test_match_images_low_confidence(self, mock_matcher_class, tmp_path):
        """Test matching with low confidence results."""
        # Setup input
        input_file = tmp_path / "input.txt"
        input_file.write_text("nginx:latest\n")

        output_file = tmp_path / "matched.csv"

        # Mock matcher
        mock_matcher = MagicMock()
        mock_matcher_class.return_value = mock_matcher

        # Mock low confidence match
        mock_matcher.match.return_value = MatchResult(
            chainguard_image="cgr.dev/chainguard/nginx:latest",
            confidence=0.5,  # Below threshold
            method="heuristic"
        )

        # Run matching
        with patch('commands.match.search_github_issues_for_images') as mock_search:
            mock_search.return_value = ([], ["nginx:latest"])  # No issue matches
            matched, unmatched = match_images(
                input_file=input_file,
                output_file=output_file,
                min_confidence=0.7,
                interactive=False,
                github_token="test-token",
            )

        # Verify low confidence is treated as unmatched
        assert len(matched) == 0
        assert len(unmatched) == 1
        assert unmatched[0] == "nginx:latest"

    @patch('commands.match.ImageMatcher')
    def test_match_images_min_confidence_threshold(self, mock_matcher_class, tmp_path):
        """Test min_confidence threshold filtering."""
        # Setup input
        input_file = tmp_path / "input.txt"
        input_file.write_text("nginx:latest\npython:3.12\n")

        output_file = tmp_path / "matched.csv"

        # Mock matcher
        mock_matcher = MagicMock()
        mock_matcher_class.return_value = mock_matcher

        # Mock match results with different confidences
        mock_matcher.match.side_effect = [
            MatchResult(
                chainguard_image="cgr.dev/chainguard/nginx-fips:latest",
                confidence=0.85,  # Above threshold
                method="heuristic"
            ),
            MatchResult(
                chainguard_image="cgr.dev/chainguard/python:latest",
                confidence=0.60,  # Below threshold
                method="heuristic"
            ),
        ]

        # Run matching with 0.7 threshold
        with patch('commands.match.search_github_issues_for_images') as mock_search:
            mock_search.return_value = ([], ["python:3.12"])  # No issue matches
            matched, unmatched = match_images(
                input_file=input_file,
                output_file=output_file,
                min_confidence=0.7,
                github_token="test-token",
            )

        # Verify threshold filtering
        assert len(matched) == 1
        assert matched[0][0] == "nginx:latest"
        assert matched[0][1].chainguard_image == "cgr.dev/chainguard/nginx-fips:latest"
        assert len(unmatched) == 1
        assert unmatched[0] == "python:3.12"


class TestInteractiveMatch:
    """Test interactive matching functionality."""

    @patch('builtins.input', return_value='y')
    def test_interactive_accept(self, mock_input):
        """Test accepting a low-confidence match."""
        result = MatchResult(
            chainguard_image="cgr.dev/chainguard/nginx:latest",
            confidence=0.65,
            method="heuristic"
        )

        matched = handle_interactive_match("nginx:latest", result)

        assert matched is not None
        assert matched == ("nginx:latest", "cgr.dev/chainguard/nginx:latest")

    @patch('builtins.input', return_value='n')
    def test_interactive_skip(self, mock_input):
        """Test skipping a low-confidence match."""
        result = MatchResult(
            chainguard_image="cgr.dev/chainguard/nginx:latest",
            confidence=0.65,
            method="heuristic"
        )

        matched = handle_interactive_match("nginx:latest", result)

        assert matched is None

    @patch('builtins.input', return_value='cgr.dev/chainguard/custom:latest')
    def test_interactive_custom_image(self, mock_input):
        """Test providing a custom image."""
        result = MatchResult(
            chainguard_image="cgr.dev/chainguard/nginx:latest",
            confidence=0.65,
            method="heuristic"
        )

        matched = handle_interactive_match("nginx:latest", result)

        assert matched is not None
        assert matched == ("nginx:latest", "cgr.dev/chainguard/custom:latest")

    @patch('builtins.input', side_effect=['1'])
    def test_interactive_select_alternative(self, mock_input):
        """Test selecting from alternatives."""
        result = MatchResult(
            chainguard_image="cgr.dev/chainguard/nginx:latest",
            confidence=0.65,
            method="heuristic",
            alternatives=[
                "cgr.dev/chainguard/nginx-fips:latest",
                "cgr.dev/chainguard/nginx-dev:latest",
            ]
        )

        matched = handle_interactive_match("nginx:latest", result)

        assert matched is not None
        assert matched == ("nginx:latest", "cgr.dev/chainguard/nginx-fips:latest")

    @patch('builtins.input', side_effect=['invalid', 'y'])
    def test_interactive_retry_on_invalid(self, mock_input):
        """Test retrying after invalid input."""
        result = MatchResult(
            chainguard_image="cgr.dev/chainguard/nginx:latest",
            confidence=0.65,
            method="heuristic"
        )

        matched = handle_interactive_match("nginx:latest", result)

        # Should eventually accept after invalid input
        assert matched is not None
        assert matched == ("nginx:latest", "cgr.dev/chainguard/nginx:latest")
        assert mock_input.call_count == 2
