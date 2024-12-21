"""
This module contains the REST API for gULP (gui Universal Log Processor).
"""

from typing import Annotated, Optional
from gulp.api.collab.structs import (
    GulpCollabFilter,
    GulpUserPermission,
    MissingPermission,
)
from gulp.api.collab.user import GulpUser
from gulp.api.collab.user_session import GulpUserSession
from gulp.api.collab_api import GulpCollab
from muty.jsend import JSendException, JSendResponse
from fastapi import Body, Depends
from gulp.api.rest.server_utils import ServerUtils
import muty.log
import muty.os
import muty.string
import muty.uploadfile
from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from muty.jsend import JSendResponse
from gulp.api.rest.structs import REGEX_CHECK_USERNAME, APIDependencies
from gulp.api.rest.test_values import TEST_REQ_ID
from muty.log import MutyLogger

router = APIRouter()


@router.put(
    "/login",
    response_model=JSendResponse,
    tags=["user"],
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701278479259,
                        "req_id": "903546ff-c01e-4875-a585-d7fa34a0d237",
                        "data": {
                            "token": "6c40c48a-f504-48ac-93fc-63948ec0c9cf",
                            "id": "admin",
                            "time_expire": 1707470710830,
                        },
                    }
                }
            }
        }
    },
    summary="login on the platform.",
    description="""
an `user_session` object is created on the `collab` database to represent a logged user.

the returned `token` is then used in all other API calls to authenticate the user.

### websocket

a `GulpUserLoginLogoutPacket` with `login: true` is sent on the `ws_id` websocket.

### configuration

related configuration parameters:

- `debug_allow_insucure_passwords`: if set to `true`, the password regex is not enforced.
- `debug_allow_any_token_as_admin`: if set to `true`, token check is skipped and an `admin` token is generated.
- `token_ttl`: the time-to-live of the token in milliseconds.
- `token_admin_ttl`: the time-to-live of the token in milliseconds for admin users.

refer to `gulp_cfg_template.json` for more information.
""",
)
async def login_handler(
    user_id: Annotated[
        str,
        Depends(APIDependencies.param_user_id),
    ],
    password: Annotated[
        str, Query(description="password for authentication.", example="admin")
    ],
    ws_id: Annotated[str, Depends(APIDependencies.param_ws_id)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    ServerUtils.dump_params(locals())
    try:
        async with GulpCollab.get_instance().session() as sess:
            s = await GulpUser.login(
                sess, user_id=user_id, password=password, ws_id=ws_id, req_id=req_id
            )
            return JSONResponse(
                JSendResponse.success(
                    req_id=req_id,
                    data={
                        "token": s.id,
                        "id": s.user_id,
                        "time_expire": s.time_expire,
                    },
                )
            )
    except Exception as ex:
        raise JSendException(ex=ex, req_id=req_id)


@router.put(
    "/logout",
    response_model=JSendResponse,
    tags=["user"],
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701278479259,
                        "req_id": "903546ff-c01e-4875-a585-d7fa34a0d237",
                        "data": {"id": "admin", "token": "token_admin"},
                    }
                }
            }
        }
    },
    summary="logout user from the platform.",
    description="""
the `user_session` object corresponding to `token` is deleted from the `collab` database.

### websocket

a `GulpUserLoginLogoutPacket` with `login: false` is sent on the `ws_id` websocket.
""",
)
async def logout_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    ws_id: Annotated[str, Depends(APIDependencies.param_ws_id)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    ServerUtils.dump_params(locals())
    try:
        async with GulpCollab.get_instance().session() as sess:
            # check permission and get user id
            s: GulpUserSession = await GulpUserSession.check_token(sess, token)
            await GulpUser.logout(sess, s, ws_id=ws_id, req_id=req_id)

            return JSONResponse(
                JSendResponse.success(
                    req_id=req_id,
                    data={"id": s.user_id, "token": token},
                )
            )
    except Exception as ex:
        raise JSendException(ex=ex, req_id=req_id)


@router.post(
    "/user_create",
    tags=["user"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1732901220291,
                        "req_id": TEST_REQ_ID,
                        "data": GulpUser.example(),
                    }
                }
            }
        }
    },
    summary="creates an user on the platform.",
    description="""
- `token` needs **admin** permission.
    """,
)
async def user_create_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    user_id: Annotated[
        str,
        Query(
            description="""
the new user id.

- `user_id` must be unique
""",
            pattern=REGEX_CHECK_USERNAME,
            example="user",
        ),
    ],
    password: Annotated[
        str,
        Depends(APIDependencies.param_password),
    ],
    permission: Annotated[
        list[GulpUserPermission],
        Depends(APIDependencies.param_permission),
    ],
    email: Annotated[
        str,
        Depends(APIDependencies.param_email_optional),
    ] = None,
    glyph_id: Annotated[str, Depends(APIDependencies.param_glyph_id_optional)] = None,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    ServerUtils.dump_params(locals())
    try:
        async with GulpCollab.get_instance().session() as sess:
            # only admin can create users
            await GulpUserSession.check_token(sess, token, GulpUserPermission.ADMIN)
            user: GulpUser = await GulpUser.create(
                sess,
                user_id,
                password,
                permission=permission,
                email=email,
                glyph_id=glyph_id,
            )
            return JSONResponse(
                JSendResponse.success(
                    req_id=req_id,
                    data=user.to_dict(exclude_none=True),
                )
            )
    except Exception as ex:
        raise JSendException(ex=ex, req_id=req_id)


@router.delete(
    "/user_delete",
    tags=["user"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701278479259,
                        "req_id": "903546ff-c01e-4875-a585-d7fa34a0d237",
                        "data": {
                            "user_id": "user",
                        },
                    }
                }
            }
        }
    },
    summary="deletes an existing user.",
    description="""
- `token` needs **admin** permission.
    """,
)
async def user_delete_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    user_id: Annotated[
        str,
        Depends(APIDependencies.param_user_id),
    ],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    ServerUtils.dump_params(locals())
    try:
        if user_id == "admin":
            raise MissingPermission('user "admin" cannot be deleted!')

        await GulpUser.delete_by_id(
            token,
            user_id,
            ws_id=None,
            req_id=req_id,
            permission=[GulpUserPermission.ADMIN],
        )
        return JSONResponse(
            JSendResponse.success(
                req_id=req_id,
                data={"id": user_id},
            )
        )

    except Exception as ex:
        raise JSendException(ex=ex, req_id=req_id)


@router.patch(
    "/user_update",
    tags=["user"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1732908917521,
                        "req_id": TEST_REQ_ID,
                        "data": GulpUser.example(),
                    }
                }
            }
        }
    },
    summary="updates an existing user on the platform.",
    description="""
- `token` needs **admin** permission if `user_id` is different from the token `user_id`, or if `permission` is set.
    
- `password`, `permission`, `email`, `glyph_id` are optional, depending on what needs to be updated, and can be set independently (**but at least one must be set**).
    """,
)
async def user_update_handler(
    token: Annotated[
        str,
        Depends(APIDependencies.param_token),
    ],
    user_id: Annotated[str, Depends(APIDependencies.param_user_id)],
    password: Annotated[
        str,
        Depends(APIDependencies.param_password_optional),
    ] = None,
    permission: Annotated[
        Optional[list[GulpUserPermission]],
        Depends(APIDependencies.param_permission_optional),
    ] = None,
    email: Annotated[
        str,
        Depends(APIDependencies.param_email_optional),
    ] = None,
    user_data: Annotated[
        dict,
        Body(
            description="user data to set.",
            example={"data1": "abcd", "data2": 1234, "data3": [1, 2, 3]},
        ),
    ] = None,
    merge_user_data: Annotated[
        bool,
        Query(
            description="if `true` (default), `user_data` is merged with the existing, if any. Either, it is replaced.",
            example=True,
        ),
    ] = True,
    glyph_id: Annotated[str, Depends(APIDependencies.param_glyph_id_optional)] = None,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    ServerUtils.dump_params(locals())
    try:
        if (
            password is None
            and permission is None
            and email is None
            and glyph_id is None
            and user_data is None
        ):
            raise ValueError(
                "at least one of password, permission, email, user_data or glyph_id must be specified."
            )

        async with GulpCollab.get_instance().session() as sess:
            from gulp.api.collab.user_session import GulpUserSession

            s: GulpUserSession = await GulpUserSession.check_token(sess, token)

            # get the user to be updated
            u: GulpUser = await GulpUser.get_by_id(sess, user_id, with_for_update=True)
            if s.user_id != u.id and not s.user.is_admin():
                raise MissingPermission("only admin can update other users.")

            d = {}
            if password:
                d["password"] = password
            if permission:
                d["permission"] = permission
            if email:
                d["email"] = email
            if glyph_id:
                d["glyph_id"] = glyph_id
            if user_data:
                if merge_user_data:
                    dd = u.user_data if u.user_data else {}
                    MutyLogger.get_instance().debug("existing user data=%s" % (dd))
                    dd.update(user_data)
                    d["user_data"] = dd
                    MutyLogger.get_instance().debug(
                        "provided user_data=%s, updated user data=%s"
                        % (user_data, d["user_data"])
                    )
                else:
                    d["user_data"] = user_data

            await u.update(sess, d, user_session=s)

            return JSONResponse(
                JSendResponse.success(req_id=req_id, data=u.to_dict(exclude_none=True))
            )
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.get(
    "/user_list",
    tags=["user"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701278479259,
                        "req_id": "903546ff-c01e-4875-a585-d7fa34a0d237",
                        "data": [GulpUser.example()],
                    }
                }
            }
        }
    },
    summary="list users.",
    description="""
- `token` needs `admin` permission.
    """,
)
async def user_list_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    ServerUtils.dump_params(locals())
    # only admin can get users list
    try:
        d = await GulpUser.get_by_filter_wrapper(
            token,
            flt=GulpCollabFilter(),
            permission=[GulpUserPermission.ADMIN],
            nested=True,
        )
        return JSendResponse.success(req_id=req_id, data=d)
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.get(
    "/user_get_by_id",
    tags=["user"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701278479259,
                        "req_id": "903546ff-c01e-4875-a585-d7fa34a0d237",
                        "data": GulpUser.example(),
                    }
                }
            }
        }
    },
    summary="get a single user.",
    description="""
- `token` needs `admin` permission to get users other than the token user.
""",
)
async def user_get_by_id(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    user_id: Annotated[str, Depends(APIDependencies.param_user_id)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    ServerUtils.dump_params(locals())
    try:
        d = await GulpUser.get_by_id_wrapper(token, user_id, nested=True)
        return JSendResponse.success(req_id=req_id, data=d)
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex
