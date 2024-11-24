from typing import override

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from gulp.api.collab.structs import GulpCollabObject, GulpCollabType, T
from gulp.api.opensearch.structs import GulpBasicDocument


class GulpStory(GulpCollabObject, type=GulpCollabType.STORY):
    """
    a story in the gulp collaboration system
    """

    documents: Mapped[list[GulpBasicDocument]] = mapped_column(
        JSONB, doc="One or more events associated with the story."
    )

    @override
    def __init__(self, *args, **kwargs):
        # initializes the base class
        super().__init__(*args, type=GulpCollabType.STORY, **kwargs)

    @classmethod
    async def create(
        cls,
        token: str,
        operation_id: str,
        name: str,
        documents: list[GulpBasicDocument],
        color: str = None,
        description: str = None,
        glyph_id: str = None,
        tags: list[str] = None,
        private: bool = False,
        ws_id: str = None,
        req_id: str = None,
        **kwargs,
    ) -> T:
        """
        Create a new story object on the collab database.

        Args:
            token(str): the token of the user creating the object, for access check
            operation_id(str): the id of the operation associated with the story
            name(str): the name of the story
            documents(list[GulpBasicDocument]): the documents associated with the story
            color(str, Optional): the color associated with the story (default: blue)
            description(str, Optional): the description of the story
            glyph_id(str, Optional): the id of the glyph associated with the story
            tags(list[str], Optional): the tags associated with the story
            private(bool, Optional): whether the story is private (default: False)
            ws_id(str, Optional): the websocket id
            req_id(str, Optional): the request id

        Returns:
            the created story object
        """
        args = {
            "operation": operation_id,
            "documents": documents,
            "glyph_id": glyph_id,
            "color": color or "blue",
            "tags": tags,
            "name": name,
            "description": description,
            "private": private,
        }
        # id is automatically generated
        return await super()._create(
            token=token,
            ws_id=ws_id,
            req_id=req_id,
            **args,
        )
