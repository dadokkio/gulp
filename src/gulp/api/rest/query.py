from asyncio import Task
import json
from muty.jsend import JSendException, JSendResponse
from typing import Annotated
from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import JSONResponse
from gulp.api.collab.stored_query import GulpStoredQuery
from gulp.api.collab.structs import (
    GulpCollabBase,
    GulpCollabFilter,
    GulpCollabType,
    GulpUserPermission,
    MissingPermission,
)
from muty.pydantic import autogenerate_model_example_by_class
from gulp.api.collab.note import GulpNote
from gulp.api.collab.user_session import GulpUserSession
from gulp.api.collab_api import GulpCollab
from gulp.api.opensearch.filters import GulpQueryFilter
from gulp.api.opensearch.query import (
    GulpQuery,
    GulpQueryHelpers,
    GulpQueryAdditionalParameters,
    GulpQuerySigmaParameters,
)
from gulp.api.opensearch.structs import GulpDocument
from gulp.api.rest.server_utils import (
    ServerUtils,
)
from sqlalchemy.ext.asyncio import AsyncSession
from gulp.api.rest.structs import APIDependencies
from gulp.api.ws_api import GulpQueryGroupMatch, GulpSharedWsQueue, GulpWsQueueDataType
from gulp.plugin import GulpPluginBase
from gulp.process import GulpProcess
from gulp.structs import GulpPluginParameters, ObjectNotFound
from muty.log import MutyLogger

import muty.string
import muty.crypto
import muty.dynload
import asyncio

router: APIRouter = APIRouter()

EXAMPLE_SIGMA_RULE = """
title: Match All Events
id: 1a070ea4-87f4-467c-b1a9-f556c56b2449
status: test
description: Matches all events in the data source
logsource:
    category: *
    product: *
detection:
    selection:
        '*': '*'
    condition: selection
falsepositives:
    - 'This rule matches everything'
level: info
"""


async def _stored_query_ids_to_gulp_query_structs(
    sess: AsyncSession, stored_query_ids: list[str]
) -> list[GulpQuery]:
    """
    get stored queries from the collab db

    Args:
        sess: the database session to use
        stored_query_ids (list[str]): list of stored query IDs
    Returns:
        list[GulpQueryStruct]: list of GulpQueryStruct
    """
    queries: list[GulpQuery] = []

    # get queries
    stored_queries: list[GulpStoredQuery] = await GulpStoredQuery.get_by_filter(
        sess, GulpCollabFilter(ids=stored_query_ids)
    )
    for qs in stored_queries:
        if qs.s_options.plugin:
            # this is a sigma query, convert
            mod = await GulpPluginBase.load(qs.s_options.plugin)
            if qs.s_options.backend is None:
                # assume local, use opensearch
                qs.s_options.backend = "opensearch"
            if qs.s_options.output_format is None:
                # assume local, use dsl_lucene
                qs.s_options.output_format = "dsl_lucene"

            # convert sigma
            qq: list[GulpQuery] = mod.sigma_convert(qs.q, qs.s_options)
            for q in qq:
                # set external
                q.external_plugin = qs.external_plugin
                if qs.tags:
                    # add stored query tags too
                    [q.tags.append(t) for t in qs.tags if t not in q.tags]

            queries.extend(qq)
            await mod.unload()
        else:
            # this is a raw query
            if not qs.external_plugin:
                # gulp local query, q is a json string
                queries.append(
                    GulpQuery(
                        name=qs.name,
                        q=json.loads(qs.q),
                        tags=qs.tags,
                        external_plugin=None,
                    )
                )
            else:
                # external query, pass q unaltered (the external plugin will handle it)
                queries.append(
                    GulpQuery(
                        name=qs.name,
                        q=qs.q,
                        tags=qs.tags,
                        external_plugin=qs.external_plugin,
                    )
                )

    return queries


async def _query_internal(
    user_id: str,
    req_id: str,
    ws_id: str,
    index: str,
    q: list[GulpQuery],
    q_options: GulpQueryAdditionalParameters,
    flt: GulpQueryFilter,
    plugin_params: GulpPluginParameters,
) -> int:
    """
    runs in a worker and perform one or more queries, streaming results to the `ws_id` websocket
    """
    if q[0].external_plugin:
        # external query, load plugin (it is guaranteed it is the same for all queries)
        mod = await GulpPluginBase.load(q[0].external_plugin)

    async with GulpCollab.get_instance().session() as sess:
        totals = 0
        for qq in q:
            try:
                if not mod:
                    # local query
                    _, hits = await GulpQueryHelpers.query_raw(
                        user_id=user_id,
                        req_id=req_id,
                        ws_id=ws_id,
                        index=index,
                        q=qq.q,
                        q_options=q_options,
                        flt=flt,
                        sess=sess,
                    )
                else:
                    # external query
                    _, hits = await mod.query_external(
                        sess,
                        user_id=user_id,
                        req_id=req_id,
                        ws_id=ws_id,
                        q_options=q_options,
                        plugin_params=plugin_params,
                    )
                totals += hits
            except Exception as ex:
                MutyLogger.get_instance().exception(ex)

    if mod:
        await mod.unload()
    return totals


async def _spawn_query_group_workers(
    user_id: str,
    req_id: str,
    ws_id: str,
    index: str,
    queries: list[GulpQuery],
    q_options: GulpQueryAdditionalParameters,
    flt: GulpQueryFilter,
    plugin_params: GulpPluginParameters,
) -> None:
    """
    spawns worker tasks for each query and wait them all
    """

    async def _worker_coro(kwds: dict):
        """
        runs in a worker

        1. run queries
        2. wait each and collect totals
        3. if all match, update note tags with group names and signal websocket with QUERY_GROUP_MATCH
        """

        tasks: list[Task] = []
        queries: list[GulpQuery] = kwds["queries"]

        for qq in queries:
            # note name set to query name
            q_options.note_parameters.note_name = qq.name

            # note tags set to query tags + this query name.
            # this will allow to identify the results in the end
            if q_options.name:
                qq.tags.append(q_options.name)
            q_options.note_parameters.note_tags = qq.tags

            # add task
            d = dict(
                user_id=user_id,
                req_id=req_id,
                ws_id=ws_id,
                index=index,
                q=qq,
                q_options=q_options,
                flt=flt,
                plugin_params=plugin_params,
            )
            tasks.append(
                GulpProcess.get_instance().process_pool.apply(_query_internal, kwds=d)
            )

        # run all and wait
        num_queries = len(queries)
        res = await asyncio.gather(*tasks, return_exceptions=True)

        # check if all sigmas matched
        query_matched = 0
        total_doc_matches = 0
        for r in res:
            if isinstance(r, int):
                query_matched += 1
                total_doc_matches += r

        if num_queries > 1 and query_matched == num_queries:
            # all queries in the group matched, change note names to query group name
            if q_options.note_parameters.create_notes:
                async with GulpCollab.get_instance().session() as sess:
                    await GulpNote.bulk_update_tag(
                        sess, [q_options.name], [q_options.group]
                    )
                    p = GulpQueryGroupMatch(
                        name=q_options.group, total_hits=total_doc_matches
                    )

            # and signal websocket
            GulpSharedWsQueue.get_instance().put(
                type=GulpWsQueueDataType.QUERY_GROUP_MATCH,
                ws_id=ws_id,
                user_id=user_id,
                req_id=req_id,
                data=p.model_dump(exclude_none=True),
            )

    MutyLogger.get_instance().debug("spawning %d queries ..." % (len(queries)))
    kwds = dict(
        user_id=user_id,
        req_id=req_id,
        ws_id=ws_id,
        index=index,
        queries=queries,
        q_options=q_options,
        flt=flt,
        plugin_params=plugin_params,
    )

    await GulpProcess.get_instance().coro_pool.spawn(_worker_coro(kwds))


@router.post(
    "/query_gulp",
    response_model=JSendResponse,
    tags=["query"],
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "pending",
                        "timestamp_msec": 1704380570434,
                        "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
                    }
                }
            }
        }
    },
    summary="the default query type for Gulp.",
    description="""
    query Gulp with filter.

    - this API returns `pending` and results are streamed to the `ws_id` websocket.
""",
)
async def query_gulp_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    index: Annotated[str, Depends(APIDependencies.param_index)],
    ws_id: Annotated[str, Depends(APIDependencies.param_ws_id)],
    flt: Annotated[GulpQueryFilter, Depends(APIDependencies.param_query_flt_optional)],
    q_options: Annotated[
        GulpQueryAdditionalParameters,
        Depends(APIDependencies.param_query_additional_parameters_optional),
    ] = None,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    params["flt"] = flt.model_dump(exclude_none=True)
    params["q_options"] = q_options.model_dump(exclude_none=True)
    ServerUtils.dump_params(params)

    try:
        async with GulpCollab.get_instance().session() as sess:
            # check token and get caller user id
            s = await GulpUserSession.check_token(sess, token)
            user_id = s.user_id

        # convert gulp query to raw query
        dsl = flt.to_opensearch_dsl()

        # spawn task to spawn worker
        qq = GulpQuery(name=None, q=dsl)
        await _spawn_query_group_workers(
            user_id=user_id,
            req_id=req_id,
            ws_id=ws_id,
            index=index,
            q=[qq],
            q_options=q_options,
        )

        # and return pending
        return JSONResponse(JSendResponse.pending(req_id=req_id))
    except Exception as ex:
        raise JSendException(ex=ex, req_id=req_id)


@router.post(
    "/query_raw",
    response_model=JSendResponse,
    tags=["query"],
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "pending",
                        "timestamp_msec": 1704380570434,
                        "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
                    }
                }
            }
        }
    },
    summary="Advanced query.",
    description="""
    query Gulp using a [raw OpenSearch query](https://opensearch.org/docs/latest/query-dsl/).

    - this API returns `pending` and results are streamed to the `ws_id` websocket.
    - `flt` may be used to restrict the query.
""",
)
async def query_raw_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    index: Annotated[str, Depends(APIDependencies.param_index)],
    ws_id: Annotated[str, Depends(APIDependencies.param_ws_id)],
    q: Annotated[
        dict,
        Body(
            description="query according to the [OpenSearch DSL specifications](https://opensearch.org/docs/latest/query-dsl/)",
            example={"query": {"match_all": {}}},
        ),
    ],
    q_options: Annotated[
        GulpQueryAdditionalParameters,
        Depends(APIDependencies.param_query_additional_parameters_optional),
    ] = None,
    flt: Annotated[
        GulpQueryFilter, Depends(APIDependencies.param_query_flt_optional)
    ] = None,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    params["flt"] = flt.model_dump(exclude_none=True)
    params["q_options"] = q_options.model_dump(exclude_none=True)
    ServerUtils.dump_params(params)

    try:
        async with GulpCollab.get_instance().session() as sess:
            # check token and get caller user id
            s = await GulpUserSession.check_token(sess, token)
            user_id = s.user_id

        # convert gulp query to raw query and spawn task
        qq = GulpQuery(name=None, q=q)
        await _spawn_query_group_workers(
            user_id=user_id,
            req_id=req_id,
            ws_id=ws_id,
            index=index,
            q=[qq],
            q_options=q_options,
            flt=flt,
        )

        # and return pending
        return JSONResponse(JSendResponse.pending(req_id=req_id))
    except Exception as ex:
        raise JSendException(ex=ex, req_id=req_id)


@router.post(
    "/query_single_id",
    response_model=JSendResponse,
    tags=["query"],
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "pending",
                        "timestamp_msec": 1704380570434,
                        "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
                        "data": autogenerate_model_example_by_class(GulpDocument),
                    }
                }
            }
        }
    },
    summary="Query a single document.",
    description="""
query Gulp for a single document using its `_id`.

### plugin_params

- for external queries, `plugin_params` must be set at least with `generic_external_parameters`.

""",
)
async def query_single_id_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    index: Annotated[str, Depends(APIDependencies.param_index)],
    doc_id: Annotated[str, Query(description="`_id` of the document on Gulp `index`.")],
    q_options: Annotated[
        GulpQueryAdditionalParameters,
        Depends(APIDependencies.param_query_additional_parameters_optional),
    ],
    plugin_params: Annotated[
        GulpPluginParameters, Depends(APIDependencies.param_plugin_params_optional)
    ] = None,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    ServerUtils.dump_params(params)

    try:
        async with GulpCollab.get_instance().session() as sess:
            # check token and get caller user id
            await GulpUserSession.check_token(sess, token)

        d = await GulpQueryHelpers.query_single(index, doc_id)
        return JSONResponse(JSendResponse.success(req_id, data=d))
    except Exception as ex:
        raise JSendException(ex=ex, req_id=req_id)


@router.post(
    "/query_sigma",
    response_model=JSendResponse,
    tags=["query"],
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "pending",
                        "timestamp_msec": 1704380570434,
                        "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
                    }
                }
            }
        }
    },
    summary="Query using sigma rule/s.",
    description="""
query using [sigma rules](https://github.com/SigmaHQ/sigma).

- this API returns `pending` and results are streamed to the `ws_id` websocket.
- `flt` may be used to restrict the query.

### q_options

- `create_notes` is set to `True` to create notes on match.
- if `sigmas` contains more than one rule, `group` must be set to indicate a `query group`.
    - if `group` is set and **all** the queries match, `QUERY_GROUP_MATCH` is sent to the websocket `ws_id` in the end and `group` is set into notes `tags`.
- `sigma_parameters.plugin` must be set to a plugin implementing `sigma_support` and `sigma_convert`, to be used to convert the sigma rule.
    - for `external` queries, the plugin must implement `query_external` as well.
- `sigma_parameters.backend` and `sigma_parameters.output_format` are ignored for `non-external` queries (internally set to `opensearch` and `dsl_lucene` respectively)

### plugin_params

- for external queries, `plugin_params` must be set at least with `generic_external_parameters`.

""",
)
async def query_sigma_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    index: Annotated[str, Depends(APIDependencies.param_index)],
    ws_id: Annotated[str, Depends(APIDependencies.param_ws_id)],
    sigmas: Annotated[
        list[str],
        Body(
            description="one or more sigma rule YAML to create the queries with.",
            example=[EXAMPLE_SIGMA_RULE],
        ),
    ],
    q_options: Annotated[
        GulpQueryAdditionalParameters,
        Depends(APIDependencies.param_query_additional_parameters_optional),
    ] = None,
    flt: Annotated[
        GulpQueryFilter, Depends(APIDependencies.param_query_flt_optional)
    ] = None,
    plugin_params: Annotated[
        GulpPluginParameters, Depends(APIDependencies.param_plugin_params_optional)
    ] = None,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    params["flt"] = flt.model_dump(exclude_none=True)
    params["q_options"] = q_options.model_dump(exclude_none=True)
    ServerUtils.dump_params(params)

    if not q_options.sigma_parameters.plugin:
        raise ValueError("`q_options.sigma_parameters.plugin must be set`")
    if len(sigmas) > 1 and not q_options.group:
        raise ValueError(
            "if more than one query is provided, `q_options.group` must be set."
        )

    # activate notes on match
    q_options.note_parameters.create_notes = True

    try:
        async with GulpCollab.get_instance().session() as sess:
            # check token and get caller user id
            s = await GulpUserSession.check_token(sess, token)
            user_id = s.user_id

        # convert sigma rule/s using pysigma
        mod = await GulpPluginBase.load(q_options.sigma_parameters.plugin)

        queries: list[GulpQuery] = []
        if not plugin_params.generic_external_parameters:
            # local gulp query
            q_options.sigma_parameters.backend = "opensearch"
            q_options.sigma_parameters.output_format = "dsl_lucene"
        if not q_options.name:
            # use an autogenerated name
            q_options.name = "query_%s" % (muty.string.generate_unique())

        for s in sigmas:
            q: list[GulpQuery] = mod.sigma_convert(s, q_options.sigma_parameters)
            for qq in q:
                if plugin_params.generic_external_parameters:
                    # set the plugin to process the query with
                    qq.external_plugin = q_options.sigma_parameters.plugin

            queries.extend(q)

        # spawn one aio task, it will spawn n multiprocessing workers and wait them
        await _spawn_query_group_workers(
            user_id=user_id,
            req_id=req_id,
            ws_id=ws_id,
            index=index,
            queries=queries,
            q_options=q_options,
            flt=flt,
            plugin_params=plugin_params,
        )

        # and return pending
        return JSONResponse(JSendResponse.pending(req_id=req_id))
    except Exception as ex:
        raise JSendException(ex=ex, req_id=req_id)


@router.post(
    "/query_stored",
    response_model=JSendResponse,
    tags=["query"],
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "pending",
                        "timestamp_msec": 1704380570434,
                        "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
                    }
                }
            }
        }
    },
    summary="Query using sigma rule/s.",
    description="""
query using queries stored on the Gulp `collab` database.

- this API returns `pending` and results are streamed to the `ws_id` websocket.
- `flt` may be used to restrict the query.

### stored_query_ids

- all `stored queries` must have the same `external_plugin` set.

### q_options

- `create_notes` is set to `True` to create notes on match.
- each `stored_query` is retrieved by id and converted if needed.
- if `stored_query_ids` contains more than one query, `group` must be set to indicate a `query group`.
    - if `group` is set and **all** the queries match, `QUERY_GROUP_MATCH` is sent to the websocket `ws_id` in the end and `group` is set into notes `tags`.
- to allow ingestion during query, `external_parameters` must be set.

#### plugin_params

- for external queries, `plugin_params` must be set at least with `generic_external_parameters`.

#### flt
- `flt` is not supported for `external` queries.

""",
)
async def query_stored(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    index: Annotated[str, Depends(APIDependencies.param_index)],
    ws_id: Annotated[str, Depends(APIDependencies.param_ws_id)],
    stored_query_ids: Annotated[
        list[str],
        Body(description="one or more stored query IDs.", example=["id1", "id2"]),
    ],
    q_options: Annotated[
        GulpQueryAdditionalParameters,
        Depends(APIDependencies.param_query_additional_parameters_optional),
    ] = None,
    flt: Annotated[
        GulpQueryFilter, Depends(APIDependencies.param_query_flt_optional)
    ] = None,
    plugin_params: Annotated[
        GulpPluginParameters, Depends(APIDependencies.param_plugin_params_optional)
    ] = None,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    params["flt"] = flt.model_dump(exclude_none=True)
    params["plugin_params"] = flt.model_dump(exclude_none=True)
    params["q_options"] = q_options.model_dump(exclude_none=True)
    ServerUtils.dump_params(params)

    if len(stored_query_ids) > 1 and not q_options.group:
        raise ValueError(
            "if more than one query is provided, `options.group` must be set."
        )

    # activate notes on match
    q_options.note_parameters.create_notes = True

    try:
        queries: list[GulpQuery] = []
        async with GulpCollab.get_instance().session() as sess:
            # check token and get caller user id
            s = await GulpUserSession.check_token(sess, token)
            user_id = s.user_id

            # get queries
            queries = await _stored_query_ids_to_gulp_query_structs(
                sess, stored_query_ids
            )

        # external queries check
        external_plugin: str = queries[0].external_plugin
        for q in queries:
            if external_plugin != q.external_plugin:
                raise ValueError("all queries must be from the same external plugin.")

        # spawn one aio task, it will spawn n multiprocessing workers and wait them
        await _spawn_query_group_workers(
            user_id=user_id,
            req_id=req_id,
            ws_id=ws_id,
            index=index,
            queries=queries,
            q_options=q_options,
            flt=flt,
            plugin_params=plugin_params,
        )

        # and return pending
        return JSONResponse(JSendResponse.pending(req_id=req_id))
    except Exception as ex:
        raise JSendException(ex=ex, req_id=req_id)


# """
# This module contains the REST API for gULP (gui Universal Log Processor).
# """

# import json
# from typing import Annotated

# import muty.crypto
# import muty.file
# import muty.jsend
# import muty.list
# import muty.log
# import muty.os
# import muty.string
# import muty.time
# import muty.uploadfile
# from fastapi import (
#     APIRouter,
#     BackgroundTasks,
#     Body,
#     File,
#     Form,
#     Header,
#     Query,
#     UploadFile,
# )
# from fastapi.responses import JSONResponse
# from muty.jsend import JSendException, JSendResponse
# from muty.log import MutyLogger

# import gulp.plugin
# import gulp.structs
# import gulp.utils
# from gulp import process
# from gulp.api import collab_api, opensearch_api, rest_api
# from gulp.api.collab.base import GulpCollabType, GulpUserPermission
# from gulp.api.collab.operation import Operation
# from gulp.api.collab.session import GulpUserSession
# from gulp.api.collab.stats import GulpStats
# from gulp.api.elastic import query_utils
# from gulp.api.elastic.query import SigmaGroupFilter, SigmaGroupFiltersParam
# from gulp.api.opensearch.filters import GulpQueryFilter
# from gulp.api.opensearch.structs import (
#     GulpQueryOptions,
#     GulpQueryParameter,
#     GulpQueryType,
# )
# from gulp.plugin import GulpPluginType
# from gulp.plugin_internal import GulpPluginParameters
# from gulp.structs import (
#     API_DESC_PYSYGMA_PLUGIN,
#     API_DESC_WS_ID,
#     InvalidArgument,
#     ObjectNotFound,
# )

# _app: APIRouter = APIRouter()


# def _sanitize_tags(tags: list[str]) -> list[str]:
#     """
#     remove empty tags
#     """
#     if tags is None:
#         return []

#     return [t.strip() for t in tags if t.strip() != ""]


# @_app.post(
#     "/query_multi",
#     response_model=JSendResponse,
#     tags=["query"],
#     response_model_exclude_none=True,
#     openapi_extra={
#         "requestBody": {
#             "content": {
#                 "application/json": {
#                     "examples": {
#                         "1": {
#                             "summary": "GulpQueryFilter",
#                             "value": {
#                                 "q": [
#                                     {
#                                         "rule": {
#                                             "start_msec": 1289373944000,
#                                             "end_msec": 1289373944000,
#                                         },
#                                         "name": "gulpqueryfilter test",
#                                         "type": 3,
#                                     }
#                                 ],
#                                 "options": {"sort": {"@timestamp": "asc"}},
#                             },
#                         },
#                         "2": {
#                             "summary": "sigma rule",
#                             "value": {
#                                 "q": [
#                                     {
#                                         "rule": "title: Test\nid: 2dcca7b4-4b3a-4db6-9364-a019d54904bf\nstatus: test\ndescription: This is a test\nreferences:\n  - ref1\n  - ref2\ntags:\n  - attack.execution\n  - attack.t1059\nauthor: me\ndate: 2020-07-12\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    EventID: 4732\n    gulp.context_id|endswith: context\n  condition: selection\nfields:\n  - EventId\n  - gulp.context_id\nfalsepositives:\n  - Everything\nlevel: medium",
#                                         "type": 1,
#                                         "name": "sigma test",
#                                         "pysigma_plugin": "windows",
#                                     }
#                                 ],
#                                 "options": {"sort": {"@timestamp": "asc"}},
#                                 "sigma_group_flts": [
#                                     {
#                                         "name": "test dummy APT",
#                                         "expr": "(87911521-7098-470b-a459-9a57fc80bdfd AND e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144)",
#                                     }
#                                 ],
#                             },
#                         },
#                         "3": {
#                             "summary": "multiple stored rules",
#                             "value": {
#                                 "q": [
#                                     {"rule": 1, "type": 4},
#                                     {"rule": 2, "type": 4},
#                                     {"rule": 3, "type": 4},
#                                 ],
#                                 "options": {"sort": {"@timestamp": "asc"}},
#                             },
#                         },
#                         "4": {
#                             "summary": "mixed",
#                             "value": {
#                                 "q": [
#                                     {
#                                         "name": "test_sigma",
#                                         "type": 1,
#                                         "rule": "title: Test\nid: 2dcca7b4-4b3a-4db6-9364-a019d54904bf\nstatus: test\ndescription: Match all *context test\nreferences:\n  - ref1\n  - ref2\ntags:\n  - attack.execution\n  - attack.test\nauthor: me\ndate: 2020-07-12\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    gulp.context_id|endswith: context\n  condition: selection\nfields:\n  - EventId\n  - gulp.context_id\nfalsepositives:\n  - Everything\nlevel: medium",
#                                         "pysigma_plugin": "windows",
#                                     },
#                                     {"rule": 1, "type": 4},
#                                     {
#                                         "name": "test_dsl",
#                                         "type": 2,
#                                         "rule": {
#                                             "bool": {
#                                                 "must": [
#                                                     {
#                                                         "query_string": {
#                                                             "query": "event.code:4732 AND gulp.context_id:*context",
#                                                             "analyze_wildcard": True,
#                                                         }
#                                                     }
#                                                 ]
#                                             }
#                                         },
#                                     },
#                                     {
#                                         "name": "test_gulpflt",
#                                         "type": 3,
#                                         "rule": {
#                                             "start_msec": 1289373944000,
#                                             "end_msec": 1289373944000,
#                                         },
#                                     },
#                                 ],
#                                 "options": {"sort": {"@timestamp": "asc"}},
#                             },
#                         },
#                     }
#                 }
#             }
#         }
#     },
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "pending",
#                         "timestamp_msec": 1704380570434,
#                         "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
#                     }
#                 }
#             }
#         }
#     },
#     summary="perform one or more queries, in parallel.",
#     description="supported:<br><br>"
#     '. **sigma rule YAML**: "rule": str<br>'
#     '. **elasticsearch DSL**: "rule": dict, "name" is mandatory<br>'
#     '. **GulpQueryFilter**: "rule": dict, "name" is mandatory<br>'
#     '. **stored query ID**: "rule": int<br><br>'
#     '*flt* may be used to restrict the query to only a subset of the data, i.e. *flt.context=["machine1"]* only.<br>'
#     "*options* is intended **per single query**.",
# )
# async def query_multi_handler(
#     bt: BackgroundTasks,
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     index: Annotated[
#         str,
#         Query(
#             description=gulp.structs.API_DESC_INDEX,
#             openapi_examples=gulp.structs.EXAMPLE_INDEX,
#         ),
#     ],
#     ws_id: Annotated[str, Query(description=API_DESC_WS_ID)],
#     q: Annotated[list[GulpQueryParameter], Body()],
#     flt: Annotated[GulpQueryFilter, Body()] = None,
#     options: Annotated[GulpQueryOptions, Body()] = None,
#     sigma_group_flts: Annotated[list[SigmaGroupFilter], Body()] = None,
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:
#     req_id = gulp.utils.ensure_req_id(req_id)
#     if flt is None:
#         flt = GulpQueryFilter()
#     if options is None:
#         options = GulpQueryOptions()

#     if options.fields_filter is None:
#         # use default fields filter
#         options.fields_filter = ",".join(query_utils.QUERY_DEFAULT_FIELDS)

#     MutyLogger.get_instance().debug(
#         "query_multi_handler, q=%s,\nflt=%s,\noptions=%s,\nsigma_group_flts=%s"
#         % (q, flt, options, sigma_group_flts)
#     )
#     user_id = None
#     try:
#         user, session = await GulpUserSession.check_token(
#             await collab_api.collab(), token, GulpUserPermission.READ
#         )
#         user_id = session.user_id
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex

#     if sigma_group_flts is not None:
#         # preprocess to avoid having to access the db while querying
#         sigma_group_flts = await query_utils.preprocess_sigma_group_filters(
#             sigma_group_flts
#         )

#     # FIXME: this is hackish ... maybe it is better to pass operation_id and client_id also for queries, without relying on the filter
#     operation_id: int = None
#     client_id: int = None
#     if flt.operation_id is not None and len(flt.operation_id) == 1:
#         operation_id = flt.operation_id[0]
#     if flt.client_id is not None and len(flt.client_id) == 1:
#         client_id = flt.client_id[0]

#     # create the request stats
#     try:
#         await GulpStats.create(
#             await collab_api.collab(),
#             GulpCollabType.STATS_QUERY,
#             req_id,
#             ws_id,
#             operation_id,
#             client_id,
#         )
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex

#     # run
#     coro = process.query_multi_task(
#         username=user.name,
#         user_id=user_id,
#         req_id=req_id,
#         flt=flt,
#         index=index,
#         q=q,
#         options=options,
#         sigma_group_flts=sigma_group_flts,
#         ws_id=ws_id,
#     )
#     await rest_api.aiopool().spawn(coro)
#     return muty.jsend.pending_jsend(req_id=req_id)


# @_app.post(
#     "/query_raw",
#     tags=["query"],
#     openapi_extra={
#         "requestBody": {
#             "content": {
#                 "application/json": {
#                     "examples": {
#                         "1": {
#                             "summary": "DSL",
#                             "value": {
#                                 "query_raw": {
#                                     "bool": {
#                                         "must": [
#                                             {
#                                                 "query_string": {
#                                                     "query": "event.code:4732 AND gulp.contextntext",
#                                                     "analyze_wildcard": True,
#                                                 }
#                                             }
#                                         ]
#                                     }
#                                 },
#                                 "options": {"sort": {"@timestamp": "asc"}},
#                             },
#                         }
#                     }
#                 }
#             }
#         }
#     },
#     response_model=JSendResponse,
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "pending",
#                         "timestamp_msec": 1704380570434,
#                         "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
#                     }
#                 }
#             }
#         }
#     },
#     summary="shortcut for query_multi() to perform a single raw query.",
#     description="[OpenSearch query DSL](https://opensearch.org/docs/latest/query-dsl/).",
# )
# async def query_raw_handler(
#     bt: BackgroundTasks,
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     index: Annotated[
#         str,
#         Query(
#             description=gulp.structs.API_DESC_INDEX,
#             openapi_examples=gulp.structs.EXAMPLE_INDEX,
#         ),
#     ],
#     ws_id: Annotated[str, Query(description=API_DESC_WS_ID)],
#     query_raw: Annotated[dict, Body()],
#     name: Annotated[
#         str, Query(description="name of the query (leave empty to autogenerate)")
#     ] = None,
#     flt: Annotated[GulpQueryFilter, Body()] = None,
#     options: Annotated[GulpQueryOptions, Body()] = None,
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:
#     gqp = GulpQueryParameter(rule=query_raw, type=GulpQueryType.RAW)
#     if name is None:
#         # generate
#         name = "raw-%s" % (muty.string.generate_unique())
#     gqp.name = name
#     return await query_multi_handler(
#         bt,
#         token,
#         index,
#         ws_id,
#         [gqp],
#         flt=flt,
#         options=options,
#         req_id=req_id,
#     )


# @_app.post(
#     "/query_gulp",
#     response_model=JSendResponse,
#     tags=["query"],
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "pending",
#                         "timestamp_msec": 1704380570434,
#                         "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
#                     }
#                 }
#             }
#         }
#     },
#     summary="shortcut for query_multi() to perform a query using GulpQueryFilter.",
#     description="internally, GulpQueryFilter is converted to a [`query_string`](https://opensearch.org/docs/latest/query-dsl/full-text/query-string/) query.",
# )
# async def query_gulp_handler(
#     bt: BackgroundTasks,
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     index: Annotated[
#         str,
#         Query(
#             description=gulp.structs.API_DESC_INDEX,
#             openapi_examples=gulp.structs.EXAMPLE_INDEX,
#         ),
#     ],
#     ws_id: Annotated[str, Query(description=API_DESC_WS_ID)],
#     flt: Annotated[GulpQueryFilter, Body()],
#     name: Annotated[
#         str, Query(description="name of the query (leave empty to autogenerate)")
#     ] = None,
#     options: Annotated[GulpQueryOptions, Body()] = None,
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:
#     # print parameters
#     MutyLogger.get_instance().debug(
#         "query_gulp_handler: flt=%s, name=%s, options=%s" % (flt, name, options)
#     )
#     gqp = GulpQueryParameter(rule=flt.to_dict(), type=GulpQueryType.GULP_FILTER)
#     if name is None:
#         # generate
#         name = "gulpfilter-%s" % (muty.string.generate_unique())

#     gqp.name = name
#     return await query_multi_handler(
#         bt, token, index, ws_id, [gqp], flt=flt, options=options, req_id=req_id
#     )


# @_app.post(
#     "/query_stored_sigma_tags",
#     response_model=JSendResponse,
#     tags=["query"],
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "pending",
#                         "timestamp_msec": 1704380570434,
#                         "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
#                     }
#                 }
#             }
#         }
#     },
#     summary="shortcut to *query_multi* to perform multiple queries by using STORED and TAGGED sigma queries (i.e. created with *stored_query_create_from_sigma_zip*)",
#     description='*flt* may be used to restrict the query to only a subset of the data, i.e. *flt.context=["machine1"]* only.<br>'
#     "*options* is intended **per single query**.",
# )
# async def query_stored_sigma_tags_handler(
#     bt: BackgroundTasks,
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     index: Annotated[
#         str,
#         Query(
#             description=gulp.structs.API_DESC_INDEX,
#             openapi_examples=gulp.structs.EXAMPLE_INDEX,
#         ),
#     ],
#     ws_id: Annotated[str, Query(description=API_DESC_WS_ID)],
#     tags: Annotated[list[str], Body()],
#     flt: Annotated[GulpQueryFilter, Body()] = None,
#     options: Annotated[GulpQueryOptions, Body()] = None,
#     sigma_group_flts: Annotated[list[SigmaGroupFilter], Body()] = None,
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:
#     MutyLogger.get_instance().debug(
#         "query_sigma_tags_handler: flt=%s, options=%s, tags=%s, sigma_group_flts=%s"
#         % (flt, options, tags, sigma_group_flts)
#     )
#     try:
#         tags = _sanitize_tags(tags)
#         if len(tags) == 0:
#             raise ObjectNotFound("no tags provided")
#         # get stored queries by tags
#         gqp = await query_utils.stored_sigma_tags_to_gulpqueryparameters(
#             await collab_api.collab(),
#             tags,
#             all_tags_must_match=options.all_tags_must_match,
#         )
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex

#     return await query_multi_handler(
#         bt,
#         token,
#         index,
#         ws_id,
#         gqp,
#         flt=flt,
#         options=options,
#         req_id=req_id,
#         sigma_group_flts=sigma_group_flts,
#     )


# @_app.post(
#     "/query_sigma",
#     response_model=JSendResponse,
#     tags=["query"],
#     openapi_extra={
#         "requestBody": {
#             "content": {
#                 "application/json": {
#                     "examples": {
#                         "1": {
#                             "summary": "sigma rule YAML",
#                             "value": {
#                                 "sigma": "title: Test\nid: 2dcca7b4-4b3a-4db6-9364-a019d54904bf\nstatus: test\ndescription: Match all *context test\nreferences:\n  - ref1\n  - ref2\ntags:\n  - attack.execution\n  - attack.test\nauthor: me\ndate: 2020-07-12\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    gulp.context_id|endswith: context\n  condition: selection\nfields:\n  - EventId\n  - gulp.context_id\nfalsepositives:\n  - Everything\nlevel: medium",
#                                 "options": {"limit": 10, "sort": {"@timestamp": "asc"}},
#                             },
#                         }
#                     }
#                 }
#             }
#         }
#     },
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "pending",
#                         "timestamp_msec": 1704380570434,
#                         "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
#                     }
#                 }
#             }
#         }
#     },
#     summary="shortcut for query_multi() to perform a query using a single sigma rule YAML.",
#     description='*flt* may be used to restrict the query to only a subset of the data, i.e. *flt.context=["machine1"]* only.<br>'
#     "*options* is intended **per single query**.",
# )
# async def query_sigma_handler(
#     bt: BackgroundTasks,
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     index: Annotated[
#         str,
#         Query(
#             description=gulp.structs.API_DESC_INDEX,
#             openapi_examples=gulp.structs.EXAMPLE_INDEX,
#         ),
#     ],
#     ws_id: Annotated[str, Query(description=API_DESC_WS_ID)],
#     sigma: Annotated[str, Body()],
#     pysigma_plugin: Annotated[
#         str,
#         Query(
#             description=API_DESC_PYSYGMA_PLUGIN,
#         ),
#     ] = None,
#     plugin_params: Annotated[GulpPluginParameters, Body()] = None,
#     flt: Annotated[GulpQueryFilter, Body()] = None,
#     options: Annotated[GulpQueryOptions, Body()] = None,
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:
#     gqp = GulpQueryParameter(
#         rule=sigma,
#         type=GulpQueryType.SIGMA_YAML,
#         pysigma_plugin=pysigma_plugin,
#         plugin_params=plugin_params,
#     )
#     return await query_multi_handler(
#         bt,
#         token,
#         index,
#         ws_id,
#         [gqp],
#         flt=flt,
#         options=options,
#         req_id=req_id,
#     )


# @_app.post(
#     "/query_sigma_files",
#     response_model=JSendResponse,
#     tags=["query"],
#     openapi_extra={
#         "requestBody": {
#             "content": {
#                 "application/json": {
#                     "examples": {
#                         "1": {
#                             "summary": "query options",
#                             "value": {
#                                 "options": {"limit": 10, "sort": {"@timestamp": "asc"}},
#                             },
#                         }
#                     }
#                 }
#             }
#         }
#     },
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "pending",
#                         "timestamp_msec": 1704380570434,
#                         "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
#                     }
#                 }
#             }
#         }
#     },
#     summary="same as query_sigma_zip, but allows to upload one or more YML files instead of a ZIP.",
#     description='*flt* may be used to restrict the query to only a subset of the data, i.e. *flt.context=["machine1"]* only.<br>'
#     "*options* is intended **per single query**.",
# )
# async def query_sigma_files_handler(
#     bt: BackgroundTasks,
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     index: Annotated[
#         str,
#         Query(
#             description=gulp.structs.API_DESC_INDEX,
#             openapi_examples=gulp.structs.EXAMPLE_INDEX,
#         ),
#     ],
#     ws_id: Annotated[str, Query(description=API_DESC_WS_ID)],
#     sigma_files: Annotated[list[UploadFile], File(description="sigma rule YAMLs.")],
#     pysigma_plugin: Annotated[
#         str,
#         Query(description=API_DESC_PYSYGMA_PLUGIN),
#     ] = None,
#     plugin_params: Annotated[GulpPluginParameters, Body()] = None,
#     tags: Annotated[list[str], Body()] = None,
#     flt: Annotated[GulpQueryFilter, Body()] = None,
#     options: Annotated[GulpQueryOptions, Body()] = None,
#     sigma_group_flts: Annotated[SigmaGroupFiltersParam, Body(...)] = None,
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:
#     req_id = gulp.utils.ensure_req_id(req_id)
#     files_path = None

#     tags = _sanitize_tags(tags)
#     try:
#         # download files to tmp
#         files_path, files = await muty.uploadfile.to_path_multi(sigma_files)
#         MutyLogger.get_instance().debug(
#             "%d files downloaded to %s ..." % (len(files), files_path)
#         )

#         # create queries and call query_multi
#         l = await query_utils.sigma_directory_to_gulpqueryparams(
#             files_path,
#             pysigma_plugin,
#             tags_from_directories=False,
#             plugin_params=plugin_params,
#             tags_filter=tags if len(tags) > 0 else None,
#             options=options,
#         )
#         return await query_multi_handler(
#             bt,
#             token,
#             index,
#             ws_id,
#             l,
#             flt=flt,
#             options=options,
#             req_id=req_id,
#             sigma_group_flts=(
#                 sigma_group_flts.sgf if sigma_group_flts is not None else None
#             ),
#         )
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex
#     finally:
#         if files_path is not None:
#             await muty.file.delete_file_or_dir_async(files_path)


# @_app.post(
#     "/query_sigma_zip",
#     response_model=JSendResponse,
#     tags=["query"],
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "pending",
#                         "timestamp_msec": 1704380570434,
#                         "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
#                     }
#                 }
#             }
#         }
#     },
#     summary="shortcut for query_multi() to perform multiple queries using sigma rule YAMLs from a zip file.",
#     description="*tags* may be used to restrict the rules used.<br>"
#     '*flt* may be used to restrict the query to only a subset of the data, i.e. *flt.context=["machine1"]* only.<br>.'
#     "*options* is intended **per single query**.",
# )
# @_app.post(
#     "/query_stored",
#     response_model=JSendResponse,
#     tags=["query"],
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "pending",
#                         "timestamp_msec": 1704380570434,
#                         "req_id": "c4f7ae9b-1e39-416e-a78a-85264099abfb",
#                     }
#                 }
#             }
#         }
#     },
#     summary="shortcut for query_multi() to perform a query using (one or more) stored query IDs.",
#     description='*flt* may be used to restrict the query to only a subset of the data, i.e. *flt.context=["machine1"]* only.<br>'
#     "*options* is intended **per single query**.",
# )
# async def query_stored_handler(
#     bt: BackgroundTasks,
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     index: Annotated[
#         str,
#         Query(
#             description=gulp.structs.API_DESC_INDEX,
#             openapi_examples=gulp.structs.EXAMPLE_INDEX,
#         ),
#     ],
#     ws_id: Annotated[str, Query(description=API_DESC_WS_ID)],
#     q: Annotated[list[int], Body()],
#     flt: Annotated[GulpQueryFilter, Body()] = None,
#     options: Annotated[GulpQueryOptions, Body()] = None,
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:

#     req_id = gulp.utils.ensure_req_id(req_id)

#     # build parameters
#     try:
#         l = []
#         for qq in q:
#             # rule name will be set when database is queried with the rule id at conversion time
#             gqp = GulpQueryParameter(rule=qq, type=GulpQueryType.INDEX)
#             l.append(gqp)
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex

#     return await query_multi_handler(
#         bt,
#         token,
#         index,
#         ws_id,
#         l,
#         flt=flt,
#         options=options,
#         req_id=req_id,
#     )


# @_app.post(
#     "/query_max_min",
#     tags=["query"],
#     response_model=JSendResponse,
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "success",
#                         "timestamp_msec": 1714474423829,
#                         "req_id": "89821150-bdef-4ff7-8586-83b75b108fea",
#                         "data": {
#                             "buckets": [
#                                 {
#                                     "*": {
#                                         "doc_count": 70814,
#                                         "max_event.code": 5158.0,
#                                         "min_@timestamp": 1475730263242.0,
#                                         "max_@timestamp": 1617234805762.0,
#                                         "min_event.code": 0.0,
#                                     }
#                                 }
#                             ],
#                             "total": 70814,
#                         },
#                     }
#                 }
#             }
#         }
#     },
#     summary='get the "@timestamp" and "gulp.event_code" range in an index, possibly aggregating per field.',
# )
# async def query_max_min_handler(
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     index: Annotated[
#         str,
#         Query(
#             description=gulp.structs.API_DESC_INDEX,
#             openapi_examples=gulp.structs.EXAMPLE_INDEX,
#         ),
#     ],
#     group_by: Annotated[str, Query(description="group by this field.")] = None,
#     flt: Annotated[GulpQueryFilter, Body()] = None,
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:

#     req_id = gulp.utils.ensure_req_id(req_id)
#     try:
#         # check token
#         await GulpUserSession.check_token(
#             await collab_api.collab(), token, GulpUserPermission.READ
#         )

#         # query
#         try:
#             res = await opensearch_api.query_max_min_per_field(
#                 opensearch_api.elastic(), index, group_by, flt
#             )
#             # MutyLogger.get_instance().debug("query_max_min_handler: %s", json.dumps(res, indent=2))
#             return JSONResponse(muty.jsend.success_jsend(req_id=req_id, data=res))
#         except ObjectNotFound:
#             # return an empty result
#             res = {"total": 0, "buckets": []}
#             return JSONResponse(muty.jsend.success_jsend(req_id=req_id, data=res))

#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex


# async def _parse_operation_aggregation(d: dict):
#     # get all operation first
#     all_ops = await Operation.get(await collab_api.collab())

#     # parse aggregations into a more readable format
#     result = []
#     for op in all_ops:
#         operation_dict = {"name": op.id, "id": op.id, "contexts": []}
#         for operation in d["aggregations"]["operations"]["buckets"]:
#             operation_key = str(operation["key"])
#             if int(operation_key) == op.id:
#                 for context in operation["context"]["buckets"]:
#                     context_key = context["key"]
#                     context_dict = {
#                         "name": context_key,
#                         "doc_count": context["doc_count"],
#                         "plugins": [],
#                     }
#                     for plugin in context["plugin"]["buckets"]:
#                         plugin_key = plugin["key"]
#                         plugin_dict = {
#                             "name": plugin_key,
#                             "src_file": [
#                                 {
#                                     "name": file["key"],
#                                     "doc_count": file["doc_count"],
#                                     "max_event.code": file["max_event.code"]["value"],
#                                     "min_event.code": file["min_event.code"]["value"],
#                                     "min_@timestamp": file["min_@timestamp"]["value"],
#                                     "max_@timestamp": file["max_@timestamp"]["value"],
#                                 }
#                                 for file in plugin["src_file"]["buckets"]
#                             ],
#                         }
#                         context_dict["plugins"].append(plugin_dict)
#                     operation_dict["contexts"].append(context_dict)
#         result.append(operation_dict)
#     return result


# @_app.get(
#     "/query_operations",
#     tags=["query"],
#     response_model=JSendResponse,
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "status": "success",
#             "timestamp_msec": 1715268048724,
#             "req_id": "07d30a97-1a4b-447a-99da-ab530402e91c",
#             "data": [
#                 {
#                     "name": "testoperation",
#                     "id": 1,
#                     "contexts": [
#                         {
#                             "name": "testcontext",
#                             "doc_count": 98630,
#                             "plugins": [
#                                 {
#                                     "name": "win_evtx",
#                                     "src_file": [
#                                         {
#                                             "name": "security_big_sample.evtx",
#                                             "doc_count": 62031,
#                                             "max_event.code": 5158.0,
#                                             "min_event.code": 1102.0,
#                                             "min_@timestamp": 1475718427166.0,
#                                             "max_@timestamp": 1475833104749.0,
#                                         },
#                                         {
#                                             "name": "2-system-Security-dirty.evtx",
#                                             "doc_count": 14621,
#                                             "max_event.code": 5061.0,
#                                             "min_event.code": 1100.0,
#                                             "min_@timestamp": 1532738204663.0,
#                                             "max_@timestamp": 1553118827379.0,
#                                         },
#                                         {
#                                             "name": "Application.evtx",
#                                             "doc_count": 6419,
#                                             "max_event.code": 12305.0,
#                                             "min_event.code": 0.0,
#                                             "min_@timestamp": 1289373941000.0,
#                                             "max_@timestamp": 1333809953000.0,
#                                         },
#                                     ],
#                                 }
#                             ],
#                         }
#                     ],
#                 }
#             ],
#         }
#     },
#     summary="query distinct operations in the given index.",
#     description="for every *operation*, results are returned aggregated per (source) *plugin* and *context*."
#     "<br><br>"
#     "for every *context*, *src_file*s are returned as well.",
# )
# async def query_operations_handler(
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     index: Annotated[
#         str,
#         Query(
#             description=gulp.structs.API_DESC_INDEX,
#             openapi_examples=gulp.structs.EXAMPLE_INDEX,
#         ),
#     ],
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:

#     req_id = gulp.utils.ensure_req_id(req_id)
#     try:
#         # check token
#         await GulpUserSession.check_token(
#             await collab_api.collab(), token, GulpUserPermission.READ
#         )
#         # query
#         res = await opensearch_api.query_operations(opensearch_api.elastic(), index)
#         MutyLogger.get_instance().debug(
#             "query_operations (before parsing): %s", json.dumps(res, indent=2)
#         )
#         res = await _parse_operation_aggregation(res)
#         return JSONResponse(muty.jsend.success_jsend(req_id=req_id, data=res))
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex


# @_app.get(
#     "/query_single_event",
#     tags=["query"],
#     response_model=JSendResponse,
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "success",
#                         "timestamp_msec": 1701879738287,
#                         "req_id": "561b55c5-6d63-498c-bcae-3114782baee2",
#                         "data": {
#                             "operation_id": "testop",
#                             "@timestamp": 1573258569309,
#                             "@timestamp_nsec": 1573258569309000000,
#                             "gulp.context_id": "testcontext2",
#                             "agent.type": "win_evtx",
#                             "agent.id": "client:test_test_1.0",
#                             "event.id": "1447406958",
#                             "log.level": 5,
#                             "gulp.log.level": 5,
#                             "gulp.source_id": "Archive-ForwardedEvents-test.evtx",
#                             "event.category": "System",
#                             "event.code": "4624",
#                             "event.duration": 0,
#                             "event.hash": "24866d6b3df4b2d2db230185e09a461886f552ae77a02c3812811e66f24a3c86",
#                             "event.original": '<?xml version="1.0" encoding="utf-8"?>\n<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">\n  <System>\n    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}">\n    </Provider>\n    <EventID>4624</EventID>\n    <Version>1</Version>\n    <Level>0</Level>\n    <Task>12544</Task>\n    <Opcode>0</Opcode>\n    <Keywords>0x8020000000000000</Keywords>\n    <TimeCreated SystemTime="2019-11-08T23:20:55.123639800Z">\n    </TimeCreated>\n    <EventRecordID>1447406958</EventRecordID>\n    <Correlation>\n    </Correlation>\n    <Execution ProcessID="512" ThreadID="5204">\n    </Execution>\n    <Channel>Security</Channel>\n    <Computer>slad1.saclink.csus.edu</Computer>\n    <Security>\n    </Security>\n  </System>\n  <EventData>\n    <Data Name="SubjectUserSid">S-1-0-0</Data>\n    <Data Name="SubjectUserName">-</Data>\n    <Data Name="SubjectDomainName">-</Data>\n    <Data Name="SubjectLogonId">0x0</Data>\n    <Data Name="TargetUserSid">S-1-5-21-6361574-1898399280-860360866-540175</Data>\n    <Data Name="TargetUserName">UL-DLN1010001$</Data>\n    <Data Name="TargetDomainName">CSUS</Data>\n    <Data Name="TargetLogonId">0x7856672d</Data>\n    <Data Name="LogonType">3</Data>\n    <Data Name="LogonProcessName">Kerberos</Data>\n    <Data Name="AuthenticationPackageName">Kerberos</Data>\n    <Data Name="WorkstationName">-</Data>\n    <Data Name="LogonGuid">{10A95F00-E9A4-D04E-4D35-8C58E0F5E502}</Data>\n    <Data Name="TransmittedServices">-</Data>\n    <Data Name="LmPackageName">-</Data>\n    <Data Name="KeyLength">0</Data>\n    <Data Name="ProcessId">0x0</Data>\n    <Data Name="ProcessName">-</Data>\n    <Data Name="IpAddress">130.86.40.27</Data>\n    <Data Name="IpPort">52497</Data>\n    <Data Name="ImpersonationLevel">%%1840</Data>\n  </EventData>\n  <RenderingInfo Culture="en-US">\n    <Message>An account was successfully logged on.\r\n\r\nSubject:\r\n\tSecurity ID:\t\tS-1-0-0\r\n\tAccount Name:\t\t-\r\n\tAccount Domain:\t\t-\r\n\tLogon ID:\t\t0x0\r\n\r\nLogon Type:\t\t\t3\r\n\r\nImpersonation Level:\t\tDelegation\r\n\r\nNew Logon:\r\n\tSecurity ID:\t\tS-1-5-21-6361574-1898399280-860360866-540175\r\n\tAccount Name:\t\tUL-DLN1010001$\r\n\tAccount Domain:\t\tCSUS\r\n\tLogon ID:\t\t0x7856672D\r\n\tLogon GUID:\t\t{10A95F00-E9A4-D04E-4D35-8C58E0F5E502}\r\n\r\nProcess Information:\r\n\tProcess ID:\t\t0x0\r\n\tProcess Name:\t\t-\r\n\r\nNetwork Information:\r\n\tWorkstation Name:\t-\r\n\tSource Network Address:\t130.86.40.27\r\n\tSource Port:\t\t52497\r\n\r\nDetailed Authentication Information:\r\n\tLogon Process:\t\tKerberos\r\n\tAuthentication Package:\tKerberos\r\n\tTransited Services:\t-\r\n\tPackage Name (NTLM only):\t-\r\n\tKey Length:\t\t0\r\n\r\nThis event is generated when a logon session is created. It is generated on the computer that was accessed.\r\n\r\nThe subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\r\n\r\nThe logon type field indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 (network).\r\n\r\nThe New Logon fields indicate the account for whom the new logon was created, i.e. the account that was logged on.\r\n\r\nThe network fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\r\n\r\nThe impersonation level field indicates the extent to which a process in the logon session can impersonate.\r\n\r\nThe authentication information fields provide detailed information about this specific logon request.\r\n\t- Logon GUID is a unique identifier that can be used to correlate this event with a KDC event.\r\n\t- Transited services indicate which intermediate services have participated in this logon request.\r\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\r\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.</Message>\n    <Level>Information</Level>\n    <Task>Logon</Task>\n    <Opcode>Info</Opcode>\n    <Channel>Security</Channel>\n    <Provider>Microsoft Windows security auditing.</Provider>\n    <Keywords>\n      <Keyword>Audit Success</Keyword>\n    </Keywords>\n  </RenderingInfo>\n</Event>',
#                             "_id": "testop-testcontext2-24866d6b3df4b2d2db230185e09a461886f552ae77a02c3812811e66f24a3c86-1573258569309",
#                         },
#                     }
#                 }
#             }
#         }
#     },
#     summary="query a single event.",
# )
# async def query_single_event_handler(
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     index: Annotated[
#         str,
#         Query(
#             description="name of the datastream to query.",
#             openapi_examples=gulp.structs.EXAMPLE_INDEX,
#         ),
#     ],
#     gulp_id: Annotated[
#         str, Query(description='the elasticsearch "_id" of the event to be retrieved.')
#     ],
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:

#     req_id = gulp.utils.ensure_req_id(req_id)
#     try:
#         # check token
#         await GulpUserSession.check_token(
#             await collab_api.collab(), token, GulpUserPermission.READ
#         )

#         # query
#         res = await opensearch_api.query_single_event(
#             opensearch_api.elastic(), index, gulp_id
#         )
#         return JSONResponse(muty.jsend.success_jsend(req_id=req_id, data=res))
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex


# @_app.post(
#     "/query_external",
#     tags=["query"],
#     response_model=JSendResponse,
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "success",
#                         "timestamp_msec": 1701879738287,
#                         "req_id": "561b55c5-6d63-498c-bcae-3114782baee2",
#                         "data": [{"GulpDocument"}, {"GulpDocument"}],
#                     }
#                 }
#             }
#         }
#     },
#     summary="query an external source.",
#     description="with this API you can query an external source (i.e. a SIEM) for data without it being ingested into GULP, using a `query_plugin` in `$PLUGIN_DIR/query`.<br><br>"
#     "GulpQueryFilter is used to filter the data from the external source, only the following fields are used and the rest is ignored:<br>"
#     '- `start_msec`: start "@timestamp"<br>'
#     '- `end_msec`: end "@timestamp"<br>'
#     '- `extra`: a dict with any extra filter to match, like: `{ "extra": { "key": "value" } }` (check `GulpBaseFilter` documentation)<br><br>'
#     "GulpQueryOptions is used to specify the following (and, as above, the rest is ignored):<br>"
#     "- `limit`: return max these entries **per chunk** on the websocket<br>"
#     "- `sort`: defaults to sort by ASCENDING timestamp<br>"
#     "- `fields_filter`: a CSV list of fields to include in the result.<br>"
#     "external source specific parameters must be provided in the `plugin_params.extra` field as a dict, i.e.<br>"
#     '`"extra": { "username": "...", "password": "...", "url": "...", "index": "...", "mapping": { "key": { "map_to": "..." } } }`',
# )
# async def query_external_handler(
#     bt: BackgroundTasks,
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     operation_id: Annotated[int, Query(description=gulp.structs.API_DESC_OPERATION)],
#     client_id: Annotated[int, Query(description=gulp.structs.API_DESC_CLIENT)],
#     ws_id: Annotated[str, Query(description=gulp.structs.API_DESC_WS_ID)],
#     plugin: Annotated[str, Query(description=gulp.structs.API_DESC_PLUGIN)],
#     plugin_params: Annotated[
#         GulpPluginParameters,
#         Body(
#             examples=[
#                 {
#                     "extra": {
#                         "username": "...",
#                         "password": "...",
#                         "url": "http://localhost:9200",
#                         "index": "testidx",
#                         "mapping": {"key": {"map_to": "...", "is_event_code": False}},
#                     }
#                 }
#             ]
#         ),
#     ],
#     flt: Annotated[
#         GulpQueryFilter,
#         Body(examples=[{"start_msec": 1475730263242, "end_msec": 1475830263242}]),
#     ],
#     options: Annotated[
#         GulpQueryOptions,
#         Body(
#             examples=[
#                 {
#                     "fields_filter": "event.original",
#                 }
#             ]
#         ),
#     ] = None,
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:
#     req_id = gulp.utils.ensure_req_id(req_id)

#     # print the request
#     MutyLogger.get_instance().debug(
#         "query_external_handler: token=%s, operation_id=%s, client_id=%s, ws_id=%s, plugin=%s, plugin_params=%s, flt=%s, options=%s, req_id=%s"
#         % (
#             token,
#             operation_id,
#             client_id,
#             ws_id,
#             plugin,
#             plugin_params,
#             flt,
#             options,
#             req_id,
#         )
#     )
#     if len(flt.to_dict()) == 0:
#         raise JSendException(req_id=req_id, ex=InvalidArgument("flt is empty!"))
#     if len(plugin_params.extra) == 0:
#         raise JSendException(
#             req_id=req_id, ex=InvalidArgument("plugin_params.extra is empty!")
#         )
#     if options is None:
#         options = GulpQueryOptions()

#     try:
#         user, _ = await GulpUserSession.check_token(
#             await collab_api.collab(), token, GulpUserPermission.READ
#         )
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex

#     # create the request stats
#     try:
#         await GulpStats.create(
#             await collab_api.collab(),
#             GulpCollabType.STATS_QUERY,
#             req_id,
#             ws_id,
#             operation_id,
#             client_id,
#         )
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex

#     # run
#     coro = process.query_external_task(
#         req_id=req_id,
#         ws_id=ws_id,
#         operation_id=operation_id,
#         client_id=client_id,
#         username=user.name,
#         user_id=user.id,
#         plugin=plugin,
#         plugin_params=plugin_params,
#         flt=flt,
#         options=options,
#     )
#     await rest_api.aiopool().spawn(coro)
#     return muty.jsend.pending_jsend(req_id=req_id)


# @_app.post(
#     "/query_external_single",
#     tags=["query"],
#     response_model=JSendResponse,
#     response_model_exclude_none=True,
#     responses={
#         200: {
#             "content": {
#                 "application/json": {
#                     "example": {
#                         "status": "success",
#                         "timestamp_msec": 1701879738287,
#                         "req_id": "561b55c5-6d63-498c-bcae-3114782baee2",
#                         "data": {"GulpDocument"},
#                     }
#                 }
#             }
#         }
#     },
#     summary="query an external source **and return a single event**.",
#     description="with this API you can query an external source (i.e. a SIEM) for data without it being ingested into GULP, using a `query_plugin` in `$PLUGIN_DIR/query`.<br><br>"
#     "this API is used to return a single event **with all fields** if `query_external` has been used to retrieve only partial data (through `fields_filter`).<br><br>"
#     "external source specific parameters must be provided in the `plugin_params.extra` field as a dict, i.e.<br>"
#     '`"extra": { "username": "...", "password": "...", "url": "...", "index": "..." }`',
# )
# async def query_external_single_handler(
#     bt: BackgroundTasks,
#     token: Annotated[str, Header(description=gulp.structs.API_DESC_TOKEN)],
#     plugin: Annotated[str, Query(description=gulp.structs.API_DESC_PLUGIN)],
#     plugin_params: Annotated[
#         GulpPluginParameters,
#         Body(
#             examples=[
#                 {
#                     "extra": {
#                         "username": "...",
#                         "password": "...",
#                         "url": "http://localhost:9200",
#                         "index": "testidx",
#                     }
#                 }
#             ]
#         ),
#     ],
#     event: Annotated[
#         dict,
#         Body(
#             examples=[
#                 {
#                     "operation_id": "testop",
#                     "@timestamp": 1573258569309,
#                     "@timestamp_nsec": 1573258569309000000,
#                     "gulp.context_id": "testcontext2",
#                     "agent.type": "win_evtx",
#                     "agent.id": "client:test_test_1.0",
#                     "event.id": "1447406958",
#                 }
#             ]
#         ),
#     ],
#     req_id: Annotated[str, Query(description=gulp.structs.API_DESC_REQID)] = None,
# ) -> JSendResponse:
#     req_id = gulp.utils.ensure_req_id(req_id)

#     # print the request
#     MutyLogger.get_instance().debug(
#         "query_external_single_handler: token=%s, plugin=%s, plugin_params=%s, event=%s, req_id=%s"
#         % (token, plugin, plugin_params, event, req_id)
#     )
#     if len(plugin_params.extra) == 0:
#         raise JSendException(
#             req_id=req_id, ex=InvalidArgument("plugin_params.extra is empty!")
#         )
#     try:
#         await GulpUserSession.check_token(
#             await collab_api.collab(), token, GulpUserPermission.READ
#         )
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex

#     # load plugin
#     mod = None
#     try:
#         mod: gulp.plugin.GulpPluginBase = gulp.plugin.load_plugin(
#             plugin, plugin_type=GulpPluginType.QUERY
#         )
#     except Exception as ex:
#         # can't load plugin ...
#         raise JSendException(req_id=req_id, ex=ex) from ex

#     try:
#         ev = await mod.query_single(
#             plugin_params,
#             event,
#         )
#         return JSONResponse(muty.jsend.success_jsend(req_id=req_id, data=ev))
#     except Exception as ex:
#         raise JSendException(req_id=req_id, ex=ex) from ex
#     finally:
#         gulp.plugin.unload_plugin(mod)


# def router() -> APIRouter:
#     """
#     Returns this module api-router, to add it to the main router

#     Returns:
#         APIRouter: The APIRouter instance
#     """
#     global _app
#     return _app
