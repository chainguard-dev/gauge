"""
Shared utilities for LLM and database operations.

This module contains common utilities used across multiple matchers
to avoid code duplication.
"""

import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator, Optional

import yaml

logger = logging.getLogger(__name__)


def parse_json_response(response_text: str) -> str:
    """
    Parse JSON from LLM response, handling markdown code blocks.

    LLMs often wrap JSON responses in markdown code blocks like:
    ```json
    {"key": "value"}
    ```

    This function strips those wrappers to get clean JSON.

    Args:
        response_text: Raw response text from LLM

    Returns:
        Cleaned JSON string ready for json.loads()
    """
    response_text = response_text.strip()
    if response_text.startswith("```json"):
        response_text = response_text[7:]
    if response_text.startswith("```"):
        response_text = response_text[3:]
    if response_text.endswith("```"):
        response_text = response_text[:-3]
    return response_text.strip()


@contextmanager
def db_connection(db_path: Path) -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager for SQLite database connections.

    Ensures connections are properly closed after use.

    Args:
        db_path: Path to SQLite database file

    Yields:
        SQLite connection object
    """
    conn = sqlite3.connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


def load_yaml_mappings(
    file_path: Path,
    description: str = "mappings",
) -> Optional[dict[str, Any]]:
    """
    Load YAML mapping file with validation and error handling.

    Args:
        file_path: Path to the YAML file
        description: Human-readable description for log messages

    Returns:
        Loaded dictionary if successful, None if file doesn't exist or is invalid
    """
    if not file_path.exists():
        logger.debug(f"No {description} file found at {file_path}")
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            logger.debug(f"{description.capitalize()} file is empty")
            return None

        if not isinstance(data, dict):
            logger.warning(f"Invalid {description} format in {file_path}")
            return None

        logger.info(f"Loaded {len(data)} {description}")
        return data

    except Exception as e:
        logger.warning(f"Failed to load {description}: {e}")
        return None
