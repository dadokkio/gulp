from typing import Optional, override

from muty.log import MutyLogger
from sqlalchemy import BIGINT, ForeignKey, Index, String, insert
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from gulp.api.collab.structs import (
    GulpCollabBase,
    GulpCollabObject,
    GulpCollabType,
    T,
)
from gulp.api.opensearch.structs import GulpBasicDocument
from gulp.api.ws_api import GulpSharedWsQueue, GulpWsQueueDataType


class GulpNote(GulpCollabObject, type=GulpCollabType.NOTE):
    """
    a note in the gulp collaboration system
    """

    context_id: Mapped[str] = mapped_column(
        ForeignKey("context.id", ondelete="CASCADE"),
        doc="The context associated with the note.",
    )
    source_id: Mapped[Optional[str]] = mapped_column(
        String, doc="The log file path (source) associated with the note."
    )
    docs: Mapped[Optional[list[GulpBasicDocument]]] = mapped_column(
        JSONB, doc="One or more GulpBasicDocument associated with the note."
    )
    time_pin: Mapped[Optional[int]] = mapped_column(
        BIGINT,
        doc="To pin the note to a specific time, in nanoseconds from the unix epoch.",
    )
    text: Mapped[Optional[str]] = mapped_column(String, doc="The text of the note.")

    __table_args__ = (Index("idx_note_operation", "operation_id"),)

    @override
    @staticmethod
    def build_dict(
        operation_id: str,
        context_id: str,
        source_id: str,
        glyph_id: str = None,
        tags: list[str] = None,
        color: str = None,
        name: str = None,
        description: str = None,
        private: bool = False,
        docs: list[GulpBasicDocument] = None,
        time_pin: int = None,
        text: str = None,
    ) -> dict:
        """
        builds a note dictionary, taking care of converting the documents to dictionaries

        Args:
            operation_id (str): the operation id
            context_id (str): the context id
            source_id (str): the source id
            glyph_id (str, optional): the glyph id. Defaults to None.
            tags (list[str], optional): the tags. Defaults to None.
            color (str, optional): the color. Defaults to None.
            name (str, optional): the name. Defaults to None.
            description (str, optional): the description. Defaults to None.
            private (bool, optional): whether the note is private. Defaults to False.
            docs (list[GulpBasicDocument], optional): the documents. Defaults to None.
            time_pin (int, optional): the time pin. Defaults to None.
            text (str, optional): the text. Defaults to None.

        Returns:
            the note dictionary
        """
        if docs:
            # convert the documents to dictionaries
            docs = [
                doc.model_dump(by_alias=True, exclude_none=True, exclude_defaults=True)
                for doc in docs
            ]
        return super().build_dict(
            operation_id=operation_id,
            context_id=context_id,
            source_id=source_id,
            glyph_id=glyph_id,
            tags=tags,
            color=color,
            name=name,
            description=description,
            private=private,
            docs=docs,
            time_pin=time_pin,
            text=text,
        )

    @staticmethod
    async def bulk_create_from_documents(
        sess: AsyncSession,
        user_id: str,
        ws_id: str,
        req_id: str,
        docs: list[dict],
        name: str,
        tags: list[str] = None,
        color: str = None,
        glyph_id: str = None,
    ) -> int:
        """
        creates a note for each document in the list, using bulk insert

        Args:
            sess (AsyncSession): the database session
            user_id (str): the user id creating the notes
            ws_id (str): the websocket id
            req_id (str): the request id
            docs (list[dict]): the list of documents to create notes for
            name (str): the name of the notes
            tags (list[str], optional): the tags to add to the notes. Defaults to None (set to ["auto"]).
            color (str, optional): the color of the notes. Defaults to None (use default).
            glyph_id (str, optional): the glyph id of the notes. Defaults to None (use default).

        Returns:
            the number of notes created
        """
        default_tags = ["auto"]
        if tags:
            # add the default tags if not already present
            tags = list(default_tags.union(tag.lower() for tag in tags))
        else:
            tags = list(default_tags)

        # create a note for each document
        notes = []
        for doc in docs:
            # associate the document with the note by creating a GulpBasicDocument object
            associated_doc = GulpBasicDocument(
                id=doc.get("_id"),
                timestamp=doc.get("@timestamp"),
                gulp_timestamp=doc.get("gulp.timestamp"),
                invalid_timestamp=doc.get("gulp.timestamp_invalid", False),
                operation_id=doc.get("gulp.operation_id"),
                context_id=doc.get("gulp.context_id"),
                source_id=doc.get("gulp.source_id"),
            )
            object_data = GulpNote.build_dict(
                operation_id=associated_doc.operation_id,
                context_id=associated_doc.context_id,
                source_id=associated_doc.source_id,
                glyph_id=glyph_id,
                tags=tags,
                color=color,
                name=name,
                docs=[associated_doc],
            )
            note_dict = GulpCollabBase.build_object_dict(
                object_data=object_data,
                type=GulpCollabType.NOTE,
                owner_id=user_id,
            )
            notes.append(note_dict)

            # bulk insert
            MutyLogger.get_instance().debug("creating %d notes" % len(notes))
            await sess.execute(insert(GulpNote).values(notes))
            await sess.commit()

            MutyLogger.get_instance().info("created %d notes" % len(notes))

            # send over the websocket
            MutyLogger.get_instance().debug(
                "sending %d notes on the websocket %s " % (len(notes), ws_id)
            )

            # operation is always the same
            operation_id = notes[0].get("operation_id")
            GulpSharedWsQueue.get_instance().put(
                GulpWsQueueDataType.COLLAB_UPDATE,
                ws_id=ws_id,
                user_id=user_id,
                operation_id=operation_id,
                req_id=req_id,
                data=notes,
            )
            MutyLogger.get_instance().debug(
                "sent %d notes on the websocket %s " % (len(notes), ws_id)
            )

            return len(notes)
