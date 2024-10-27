from typing import Optional, override
from sqlalchemy import String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.ext.asyncio import AsyncSession
from gulp.api.collab.structs import GulpCollabType, GulpCollabObject, T
from gulp.api.elastic.structs import GulpAssociatedDocument
from gulp.utils import logger


class GulpStory(GulpCollabObject):
    """
    a story in the gulp collaboration system
    """

    __tablename__ = GulpCollabType.STORY

    documents: Mapped[list[GulpAssociatedDocument]] = mapped_column(
        JSONB, doc="One or more events associated with the story."
    )
    text: Mapped[Optional[str]] = mapped_column(
        String, default=None, doc="The description of the story."
    )

    __mapper_args__ = {
        f"polymorphic_identity": {GulpCollabType.STORY},
    }

    @override
    @classmethod
    async def create(
        cls,
        id: str,
        user: str | "GulpUser",
        operation: str,
        documents: list[GulpAssociatedDocument],
        text: str = None,
        glyph: str = None,
        tags: list[str] = None,
        title: str = None,
        private: bool = False,
        ws_id: str = None,
        req_id: str = None,
        sess: AsyncSession = None,
        commit: bool = True,
        **kwargs,
    ) -> T:
        args = {
            "operation": operation,
            "documents": documents,
            "glyph": glyph,
            "tags": tags,
            "title": title,
            "text": text,
            "private": private,
        }
        return await super()._create(
            id,
            user,
            ws_id,
            req_id,
            sess,
            commit,
            **args,
        )
