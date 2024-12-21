"""
gulp stored_queries rest api
"""

from muty.jsend import JSendException, JSendResponse
from typing import Annotated, Optional
from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import JSONResponse
from gulp.api.collab.stored_query import GulpStoredQuery
from gulp.api.collab.structs import (
    GulpCollabFilter,
)
from gulp.api.opensearch.query import (
    GulpQuerySigmaParameters,
)
from gulp.api.rest.server_utils import (
    ServerUtils,
)

from gulp.api.rest.structs import APIDependencies

router: APIRouter = APIRouter()


@router.post(
    "/stored_query_create",
    tags=["stored_query"],
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
                        "data": GulpStoredQuery.example(),
                    }
                }
            }
        }
    },
    summary="creates a stored_query.",
    description="""
creates a stored query.

a stored query is a *reusable* query (or query group) which may be shared with other users.

- `token` needs `edit` permission.
- if `text` is provided and it is a valid sigma rule, the `id` is extracted from the rule and used as the stored query id.
""",
)
async def stored_query_create_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    name: Annotated[str, Depends(APIDependencies.param_display_name)],
    q: Annotated[
        str,
        Body(description="a query as string."),
    ],
    q_groups: Annotated[
        Optional[list[str]],
        Body(
            description="if set, one or more `query groups` to associate with this query.",
        ),
    ] = None,
    s_options: Annotated[
        GulpQuerySigmaParameters,
        Body(
            description="for a `sigma query`, these must be set for the `sigma rule` conversion."
        ),
    ] = None,
    tags: Annotated[list[str], Depends(APIDependencies.param_tags_optional)] = None,
    description: Annotated[
        str, Depends(APIDependencies.param_description_optional)
    ] = None,
    glyph_id: Annotated[str, Depends(APIDependencies.param_glyph_id_optional)] = None,
    private: Annotated[bool, Depends(APIDependencies.param_private_optional)] = False,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    params["s_options"] = s_options.model_dump(exclude_none=True) if s_options else None
    ServerUtils.dump_params(params)
    try:
        object_data = {
            "name": name,
            "q": q,
            "q_groups": q_groups,
            "s_options": s_options.model_dump(exclude_none=True) if s_options else None,
            "tags": tags,
            "description": description,
            "glyph_id": glyph_id,
        }
        q_id: str = None
        d = await GulpStoredQuery.create(
            token,
            ws_id=None,  # do not propagate on the websocket
            req_id=req_id,
            object_data=object_data,
            id=q_id,
            private=private,
        )
        return JSONResponse(JSendResponse.success(req_id=req_id, data=d))
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.patch(
    "/stored_query_update",
    tags=["stored_query"],
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
                        "data": GulpStoredQuery.example(),
                    }
                }
            }
        }
    },
    summary="updates an existing stored_query.",
    description="""
- `token` needs `edit` permission (or be the owner of the object, or admin) to update the object.
""",
)
async def stored_query_update_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    object_id: Annotated[str, Depends(APIDependencies.param_object_id)],
    name: Annotated[str, Depends(APIDependencies.param_display_name_optional)],
    q: Annotated[
        list[str],
        Body(description="one or more queries as string."),
    ],
    q_groups: Annotated[
        Optional[list[str]],
        Body(
            description="if set, one or more `query groups` to associate with this query.",
        ),
    ] = None,
    s_options: Annotated[
        GulpQuerySigmaParameters,
        Body(
            description="for a `sigma query`, these must be set for the `sigma rule` conversion."
        ),
    ] = None,
    tags: Annotated[list[str], Depends(APIDependencies.param_tags_optional)] = None,
    description: Annotated[
        str, Depends(APIDependencies.param_description_optional)
    ] = None,
    glyph_id: Annotated[str, Depends(APIDependencies.param_glyph_id_optional)] = None,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    params["s_options"] = s_options.model_dump(exclude_none=True) if s_options else None
    ServerUtils.dump_params(params)
    try:
        if not any([q, q_groups, tags, description, glyph_id, s_options]):
            raise ValueError(
                "At least one of q, q_groups, tags, description, glyph_id, s_options must be provided."
            )
        d = {}
        if name:
            d["name"] = name
        if q:
            d["q"] = q
        if q_groups:
            d["q_groups"] = q_groups
        if tags:
            d["tags"] = tags
        if description:
            d["description"] = description
        if glyph_id:
            d["glyph_id"] = glyph_id
        if s_options:
            d["s_options"] = s_options.model_dump(exclude_none=True)
        d = await GulpStoredQuery.update_by_id(
            token,
            object_id,
            ws_id=None,  # do not propagate on the websocket
            req_id=req_id,
            d=d,
        )
        return JSONResponse(JSendResponse.success(req_id=req_id, data=d))
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.delete(
    "/stored_query_delete",
    tags=["stored_query"],
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
                        "data": {"id": "obj_id"},
                    }
                }
            }
        }
    },
    summary="deletes a stored_query.",
    description="""
- `token` needs either to have `delete` permission, or be the owner of the object, or be an admin.
""",
)
async def stored_query_delete_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    object_id: Annotated[str, Depends(APIDependencies.param_object_id)],
    ws_id: Annotated[str, Depends(APIDependencies.param_ws_id)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    ServerUtils.dump_params(locals())
    try:
        await GulpStoredQuery.delete_by_id(
            token,
            object_id,
            ws_id=ws_id,
            req_id=req_id,
        )
        return JSendResponse.success(req_id=req_id, data={"id": object_id})
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.get(
    "/stored_query_get_by_id",
    tags=["stored_query"],
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
                        "data": GulpStoredQuery.example(),
                    }
                }
            }
        }
    },
    summary="gets a stored_query.",
)
async def stored_query_get_by_id_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    object_id: Annotated[str, Depends(APIDependencies.param_object_id)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSendResponse:
    ServerUtils.dump_params(locals())
    try:
        d = await GulpStoredQuery.get_by_id_wrapper(
            token,
            object_id,
        )
        return JSendResponse.success(req_id=req_id, data=d)
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.post(
    "/stored_query_list",
    tags=["stored_query"],
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
                        "data": [
                            GulpStoredQuery.example(),
                        ],
                    }
                }
            }
        }
    },
    summary="list stored_queries, optionally using a filter.",
    description="",
)
async def stored_query_list_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    flt: Annotated[
        GulpCollabFilter, Depends(APIDependencies.param_collab_flt_optional)
    ] = None,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    params["flt"] = flt.model_dump(exclude_none=True, exclude_defaults=True)
    ServerUtils.dump_params(params)
    try:
        d = await GulpStoredQuery.get_by_filter_wrapper(
            token,
            flt,
        )
        return JSendResponse.success(req_id=req_id, data=d)
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex
