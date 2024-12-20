from gulp.api.collab.structs import GulpCollabType
from tests.api.common import GulpAPICommon
from muty.log import MutyLogger


class GulpAPIObjectACL:
    """
    bindings to call gulp's object acl related API endpoints
    """

    @staticmethod
    async def _object_make_public_or_private(
        token: str,
        object_id: str,
        object_type: GulpCollabType,
        private: bool,
        expected_status: int = 200,
    ) -> dict:
        api_common = GulpAPICommon.get_instance()
        MutyLogger.get_instance().info(
            "Making object %s public/private, private=%r" % (object_id, private)
        )
        if private:
            api = "object_make_private"
        else:
            api = "object_make_public"
        params = {
            "object_id": object_id,
            "type": object_type.value,
            "req_id": api_common.req_id,
        }
        res = await api_common.make_request(
            "PATCH",
            api,
            params=params,
            token=token,
            expected_status=expected_status,
        )
        return res

    @staticmethod
    async def object_make_public(
        token: str,
        object_id: str,
        object_type: GulpCollabType,
        expected_status: int = 200,
    ) -> dict:
        return await GulpAPIObjectACL._object_make_public_or_private(
            token,
            object_id=object_id,
            object_type=object_type,
            private=False,
            expected_status=expected_status,
        )

    @staticmethod
    async def object_make_private(
        token: str,
        object_id: str,
        object_type: GulpCollabType,
        expected_status: int = 200,
    ) -> dict:
        return await GulpAPIObjectACL._object_make_public_or_private(
            token,
            object_id=object_id,
            object_type=object_type,
            private=True,
            expected_status=expected_status,
        )

    @staticmethod
    async def _object_add_remove_granted_user(
        token: str,
        object_id: str,
        object_type: GulpCollabType,
        user_id: str,
        remove: bool,
        expected_status: int = 200,
    ) -> dict:
        api_common = GulpAPICommon.get_instance()
        MutyLogger.get_instance().info(
            "Adding/removing user grant on object %s, user %s, remove=%r"
            % (object_id, user_id, remove)
        )
        if remove:
            api = "object_remove_granted_user"
        else:
            api = "object_add_granted_user"
        params = {
            "object_id": object_id,
            "type": object_type.value,
            "user_id": user_id,
            "req_id": api_common.req_id,
        }
        res = await api_common.make_request(
            "PATCH",
            api,
            params=params,
            token=token,
            expected_status=expected_status,
        )
        return res

    @staticmethod
    async def object_add_granted_user(
        token: str,
        object_id: str,
        object_type: GulpCollabType,
        user_id: str,
        expected_status: int = 200,
    ) -> dict:
        return await GulpAPIObjectACL._object_add_remove_granted_user(
            token,
            object_id=object_id,
            object_type=object_type,
            user_id=user_id,
            remove=False,
            expected_status=expected_status,
        )

    @staticmethod
    async def object_remove_granted_user(
        token: str,
        object_id: str,
        object_type: GulpCollabType,
        user_id: str,
        expected_status: int = 200,
    ) -> dict:
        return await GulpAPIObjectACL._object_add_remove_granted_user(
            token,
            object_id=object_id,
            object_type=object_type,
            user_id=user_id,
            remove=True,
            expected_status=expected_status,
        )

    @staticmethod
    async def _object_add_remove_granted_group(
        token: str,
        object_id: str,
        object_type: GulpCollabType,
        group_id: str,
        remove: bool,
        expected_status: int = 200,
    ) -> dict:
        api_common = GulpAPICommon.get_instance()
        MutyLogger.get_instance().info(
            "Adding group grant, object %s, group %s, remove=%r"
            % (object_id, group_id, remove)
        )
        if remove:
            api = "object_remove_granted_group"
        else:
            api = "object_add_granted_group"
        params = {
            "object_id": object_id,
            "type": object_type.value,
            "group_id": group_id,
            "req_id": api_common.req_id,
        }
        res = await api_common.make_request(
            "PATCH",
            api,
            params=params,
            token=token,
            expected_status=expected_status,
        )
        return res

    @staticmethod
    async def object_add_granted_group(
        token: str,
        object_id: str,
        object_type: GulpCollabType,
        group_id: str,
        expected_status: int = 200,
    ) -> dict:
        return await GulpAPIObjectACL._object_add_remove_granted_group(
            token,
            object_id=object_id,
            object_type=object_type,
            group_id=group_id,
            remove=False,
            expected_status=expected_status,
        )

    @staticmethod
    async def object_remove_granted_group(
        token: str,
        object_id: str,
        object_type: GulpCollabType,
        group_id: str,
        expected_status: int = 200,
    ) -> dict:
        return await GulpAPIObjectACL._object_add_remove_granted_group(
            token,
            object_id=object_id,
            object_type=object_type,
            group_id=group_id,
            remove=True,
            expected_status=expected_status,
        )
