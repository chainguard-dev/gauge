"""
Reprocessing queue for failed image pulls.

Handles tracking and retry of images that failed to pull due to transient
network issues, rate limiting, or temporary server problems.
"""

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class FailedImagePull:
    """Record of a failed image pull attempt."""

    image: str
    """Original image reference that failed"""

    platform: Optional[str]
    """Platform specification used for the pull"""

    error_message: str
    """Error message from the failed pull"""

    error_type: str
    """Type of error ('auth', 'timeout', 'rate_limit', 'not_found', 'unknown')"""

    context: str
    """Context about where this image was being used (e.g., 'alternative' or 'chainguard')"""

    pair_index: Optional[int] = None
    """Index of the image pair this belongs to (if applicable)"""


class RetryQueue:
    """
    Queue for managing failed image pulls and their retries.

    Tracks images that failed to pull during the main scan phase
    and provides retry functionality at the end of the run.
    """

    def __init__(self):
        """Initialize an empty retry queue."""
        self._queue: list[FailedImagePull] = []

    def add(
        self,
        image: str,
        platform: Optional[str],
        error_message: str,
        error_type: str,
        context: str,
        pair_index: Optional[int] = None
    ) -> None:
        """
        Add a failed image pull to the retry queue.

        Args:
            image: Image reference that failed to pull
            platform: Platform specification used
            error_message: Error message from the failure
            error_type: Type of error from the failure
            context: Context string (e.g., 'alternative', 'chainguard')
            pair_index: Index of the image pair (if applicable)
        """
        failed_pull = FailedImagePull(
            image=image,
            platform=platform,
            error_message=error_message,
            error_type=error_type,
            context=context,
            pair_index=pair_index
        )
        self._queue.append(failed_pull)
        logger.debug(f"Added {image} to retry queue (context: {context})")

    def get_all(self) -> list[FailedImagePull]:
        """
        Get all failed pulls in the queue.

        Returns:
            List of all FailedImagePull records
        """
        return self._queue.copy()

    def size(self) -> int:
        """
        Get the number of items in the retry queue.

        Returns:
            Queue size
        """
        return len(self._queue)

    def clear(self) -> None:
        """Clear the retry queue."""
        self._queue.clear()

    def is_empty(self) -> bool:
        """
        Check if the retry queue is empty.

        Returns:
            True if queue is empty, False otherwise
        """
        return len(self._queue) == 0

    def remove(self, failed_pull: FailedImagePull) -> bool:
        """
        Remove a specific failed pull from the queue.

        Args:
            failed_pull: The FailedImagePull record to remove

        Returns:
            True if item was found and removed, False otherwise
        """
        try:
            self._queue.remove(failed_pull)
            logger.debug(f"Removed {failed_pull.image} from retry queue")
            return True
        except ValueError:
            return False
