from typing import Optional, override
from sqlalchemy import BIGINT, ForeignKey, Index, String, ARRAY, Boolean, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from gulp.api.collab.structs import (
    COLLAB_MAX_NAME_LENGTH,
    GulpCollabType,
    GulpCollabObject,
)
from gulp.api.elastic.structs import GulpAssociatedDocument
from gulp.utils import logger


class GulpStory(GulpCollabObject):
    """
    a story in the gulp collaboration system
    """

    __tablename__ = "story"

    # the following must be refactored for specific tables
    id: Mapped[int] = mapped_column(
        ForeignKey("collab_obj.id"),
        primary_key=True,
        doc="The unique identifier (name) of the story.",
    )
    events: Mapped[list[GulpAssociatedDocument]] = mapped_column(
        JSONB, doc="One or more events associated with the story."
    )
    text: Mapped[Optional[str]] = mapped_column(
        String, default=None, doc="The description of the story."
    )

    __mapper_args__ = {
        "polymorphic_identity": "story",
    }

    @override
    def __init__(
        self,
        id: str,
        user: str,
        operation: str,
        events: list[GulpAssociatedDocument],
        text: str = None,
        **kwargs,
    ) -> None:
        """
        Initialize a GulpStory instance.
        Args:
            id (str): The unique identifier for the story.
            user (str): The user associated with the story.
            operation (str): The operation performed on the story.
            events (list[GulpAssociatedDocument]): A list of associated document events.
            text (str, optional): The text content of the story. Defaults to None.
            **kwargs: Additional keyword arguments passed to the GulpCollabObject initializer.
        Returns:
            None
        """
        super().__init__(id, GulpCollabType.STORY, user, operation, **kwargs)
        self.events = events
        self.text = text
        logger().debug("---> GulpStory: events=%s, text=%s" % (events, text))
