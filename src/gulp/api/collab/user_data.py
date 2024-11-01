from typing import Union, override
from sqlalchemy import ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column, relationship

from gulp.api.collab.structs import GulpCollabBase, GulpCollabFilter, GulpCollabType, T
from gulp.utils import logger


class GulpUserData(GulpCollabBase, type=GulpCollabType.USER_DATA):
    """
    defines data associated with an user
    """

    user_id: Mapped[str] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"),
        doc="The user ID associated with this data.",
        unique=True,
    )
    user: Mapped["GulpUser"] = relationship(
        "GulpUser",
        back_populates="user_data",
        foreign_keys="[GulpUser.user_data_id]",
        cascade="all,delete-orphan",
        single_parent=True,
        uselist=False,
    )
    data: Mapped[dict] = mapped_column(
        JSONB, doc="The data to be associated with user."
    )

    @classmethod    
    async def create(
        cls,
        id: str,
        owner: str,
        data: dict,
        token: str = None,
        ws_id: str = None,
        req_id: str = None,
        **kwargs,
    ) -> T:
        """
        Asynchronously creates a new user data entry.
        Args:
            id (str): The unique identifier for the user data entry.
            owner (str): The owner of the user data entry.
            data (dict): The data to be stored in the user data entry.
            token (str, optional): The authentication token. Defaults to None (no check).
            ws_id (str, optional): The websocket ID. Defaults to None.
            req_id (str, optional): The request ID. Defaults to None.
            **kwargs: Additional keyword arguments.
        Returns:
            T: The created user data entry.
        """        
        args = {
            "data": data,
        }
        return await super()._create(
            id,
            owner,
            token=token,
            ws_id=ws_id,
            req_id=req_id,
            **args,
        )
