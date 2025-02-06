from collections import defaultdict
import gc
import inspect
import os
import json
import base64
import time
import muty.file
import muty.obj
import psutil
from gulp.api.mapping.models import GulpMappingFile
import sys
from gulp.plugin import GulpPluginBase
from gulp.api.rest_api import GulpRestServer
from muty.jsend import JSendException, JSendResponse
from typing import Annotated
from fastapi import APIRouter, UploadFile, File, Depends, Query
from fastapi.responses import JSONResponse
from gulp.api.collab.stats import GulpRequestStats
from gulp.api.collab.user_session import GulpUserSession
from gulp.api.collab_api import GulpCollab
from gulp.api.rest.server_utils import (
    ServerUtils,
)
from gulp.api.collab.structs import (
    GulpCollabFilter,
    GulpRequestStatus,
    GulpUserPermission,
)
from gulp.config import GulpConfig
from gulp.api.rest.structs import APIDependencies
from gulp.api.rest.test_values import TEST_REQ_ID
from muty.log import MutyLogger
import muty.file
import muty.uploadfile

from gulp.structs import ObjectAlreadyExists

router: APIRouter = APIRouter()


@router.post(
    "/request_cancel",
    tags=["request"],
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
                        "data": {"id": "test_req"},
                    }
                }
            }
        }
    },
    summary="cancel a request.",
    description="""
set a running request `status` to `CANCELED`.

- `token` needs `admin` permission or to be the owner of the request.
""",
)
async def request_cancel_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    req_id_to_cancel: Annotated[
        str, Query(description="request id to cancel.", example=TEST_REQ_ID)
    ],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    ServerUtils.dump_params(params)
    try:
        async with GulpCollab.get_instance().session() as sess:
            stats: GulpRequestStats = await GulpRequestStats.get_by_id(
                sess, req_id_to_cancel
            )
            s = await GulpUserSession.check_token(
                sess, token, obj=stats, enforce_owner=True
            )
            await stats.cancel(sess, s.user_id)
        return JSendResponse.success(req_id=req_id, data={"id": req_id_to_cancel})
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.post(
    "/request_list",
    tags=["request"],
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
                        "data": {"id": "test_req"},
                    }
                }
            }
        }
    },
    summary="get requests list.",
    description="""
get a list of all requests (identified by their `req_id`) issued by the calling user.

- if token has `admin` permission, all requests are returned.

""",
)
async def request_list_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    running_only: Annotated[
        bool, Query(description="if set, only return requests that are still running.")
    ] = False,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    ServerUtils.dump_params(params)
    try:
        if running_only:
            # only return ongoing requests
            flt = GulpCollabFilter(completed=["0"])            
        else:
            # all requests
            flt = None
        
        stats: list[dict] = await GulpRequestStats.get_by_filter_wrapper(token, flt)
        return JSendResponse.success(req_id=req_id, data=stats)
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex

@router.post(
    "/restart_server",
    tags=["utility"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701278479259,
                        "req_id": "903546ff-c01e-4875-a585-d7fa34a0d237"
                    }
                }
            }
        }
    },
    summary="""restart the server.
    """,
    description="""
use i.e. to apply changes to the server configuration or plugins, or if the server gets slow or consumes too much memory.

- token needs `admin` permission.    
    """
)
async def restart_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    params = locals()
    ServerUtils.dump_params(params)
    async with GulpCollab.get_instance().session() as sess:
        await GulpUserSession.check_token(sess, token, GulpUserPermission.ADMIN)

    GulpRestServer.get_instance().trigger_restart()
    return JSendResponse.success(req_id=req_id)


@router.post(
    "/status",
    tags=["utility"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1738176594947,
                        "req_id": "test_req",
                        "data": {
                            "memory": {
                                "total": 31490994176,
                                "available": 17274675200,
                                "percent": 45.1,
                                "used": 12644323328,
                                "free": 15703216128
                            },
                            "cpu": {
                                "percent": 36.6,
                                "count": 8,
                                "freq": {
                                    "current": 3135.96325,
                                    "min": 1400.0,
                                    "max": 2100.0
                                }
                            },
                            "disk": {
                                "total": 467783827456,
                                "used": 215005560832,
                                "free": 228940931072,
                                "percent": 48.4
                            },
                            "processes": [
                                {
                                    "pid": 52220,
                                    "name": "gulp",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 148799488,
                                        "rss_mb": 141.90625,
                                        "vms": 964345856,
                                        "vms_mb": 919.671875,
                                        "shared": 5677056,
                                        "shared_mb": 5.4140625
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 /home/vscode/.local/bin/gulp",
                                    "username": "vscode"
                                },
                                {
                                    "pid": 52234,
                                    "name": "python3.13",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 13586432,
                                        "rss_mb": 12.95703125,
                                        "vms": 19591168,
                                        "vms_mb": 18.68359375,
                                        "shared": 6639616,
                                        "shared_mb": 6.33203125
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 -c from multiprocessing.resource_tracker import main;main(14)",
                                    "username": "vscode"
                                },
                                {
                                    "pid": 52235,
                                    "name": "python3.13",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 140615680,
                                        "rss_mb": 134.1015625,
                                        "vms": 332206080,
                                        "vms_mb": 316.81640625,
                                        "shared": 26664960,
                                        "shared_mb": 25.4296875
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=15, pipe_handle=25) --multiprocessing-fork",
                                    "username": "vscode"
                                },
                                {
                                    "pid": 52270,
                                    "name": "python3.13",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 145494016,
                                        "rss_mb": 138.75390625,
                                        "vms": 333705216,
                                        "vms_mb": 318.24609375,
                                        "shared": 29970432,
                                        "shared_mb": 28.58203125
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=15, pipe_handle=23) --multiprocessing-fork",
                                    "username": "vscode"
                                },
                                {
                                    "pid": 52274,
                                    "name": "python3.13",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 145592320,
                                        "rss_mb": 138.84765625,
                                        "vms": 409251840,
                                        "vms_mb": 390.29296875,
                                        "shared": 29945856,
                                        "shared_mb": 28.55859375
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=15, pipe_handle=27) --multiprocessing-fork",
                                    "username": "vscode"
                                },
                                {
                                    "pid": 52278,
                                    "name": "python3.13",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 145539072,
                                        "rss_mb": 138.796875,
                                        "vms": 333742080,
                                        "vms_mb": 318.28125,
                                        "shared": 29908992,
                                        "shared_mb": 28.5234375
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=15, pipe_handle=29) --multiprocessing-fork",
                                    "username": "vscode"
                                },
                                {
                                    "pid": 52282,
                                    "name": "python3.13",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 145559552,
                                        "rss_mb": 138.81640625,
                                        "vms": 409288704,
                                        "vms_mb": 390.328125,
                                        "shared": 30007296,
                                        "shared_mb": 28.6171875
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=15, pipe_handle=31) --multiprocessing-fork",
                                    "username": "vscode"
                                },
                                {
                                    "pid": 52286,
                                    "name": "python3.13",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 145637376,
                                        "rss_mb": 138.890625,
                                        "vms": 409243648,
                                        "vms_mb": 390.28515625,
                                        "shared": 29990912,
                                        "shared_mb": 28.6015625
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=15, pipe_handle=33) --multiprocessing-fork",
                                    "username": "vscode"
                                },
                                {
                                    "pid": 52290,
                                    "name": "python3.13",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 145661952,
                                        "rss_mb": 138.9140625,
                                        "vms": 333701120,
                                        "vms_mb": 318.2421875,
                                        "shared": 30146560,
                                        "shared_mb": 28.75
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=15, pipe_handle=35) --multiprocessing-fork",
                                    "username": "vscode"
                                },
                                {
                                    "pid": 52294,
                                    "name": "python3.13",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 145764352,
                                        "rss_mb": 139.01171875,
                                        "vms": 333684736,
                                        "vms_mb": 318.2265625,
                                        "shared": 30015488,
                                        "shared_mb": 28.625
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=15, pipe_handle=37) --multiprocessing-fork",
                                    "username": "vscode"
                                },
                                {
                                    "pid": 52298,
                                    "name": "python3.13",
                                    "cpu_percent": 0.0,
                                    "memory_info": {
                                        "rss": 145625088,
                                        "rss_mb": 138.87890625,
                                        "vms": 333623296,
                                        "vms_mb": 318.16796875,
                                        "shared": 29974528,
                                        "shared_mb": 28.5859375
                                    },
                                    "status": "sleeping",
                                    "cmdline": "/usr/local/bin/python3.13 -c from multiprocessing.spawn import spawn_main; spawn_main(tracker_fd=15, pipe_handle=39) --multiprocessing-fork",
                                    "username": "vscode"
                                }
                            ]
                        }
                    }
                }
            }
        }
    },
    summary="""gets gulp health status.
    """,
    description="""
gets detailed gulp server health status, including memory, cpu, disk usage, and running processes.

- token needs `admin` permission.    
    """
)
async def server_stats_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    gulp_only: Annotated[bool, Query(
        description="if set, only return process information for gulp processes only. either, return process information for all the running processes.")] = True,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:

    params = locals()
    ServerUtils.dump_params(params)
    async with GulpCollab.get_instance().session() as sess:
        await GulpUserSession.check_token(sess, token, GulpUserPermission.ADMIN)

    def _get_process_info(proc, gulp_only):
        # check if the process is the current pid, or a child of the current pid
        if gulp_only and proc.ppid() != os.getpid():
            return None

        try:
            mem_inffo = proc.memory_info()
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "cpu_percent": proc.cpu_percent(),
                "memory_info": {
                    "rss": mem_inffo.rss,
                    "rss_mb": mem_inffo.rss / 1024 / 1024,
                    "vms": mem_inffo.vms,
                    "vms_mb": mem_inffo.vms / 1024 / 1024,
                    "shared": mem_inffo.shared,
                    "shared_mb": mem_inffo.shared / 1024 / 1024,
                },
                "status": proc.status(),
                "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "",
                "username": proc.username(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    # Get system stats
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    stats = {
        "memory": {
            "total": memory.total,
            "available": memory.available,
            "percent": memory.percent,
            "used": memory.used,
            "free": memory.free
        },
        "cpu": {
            "percent": psutil.cpu_percent(interval=1),
            "count": psutil.cpu_count(),
            "freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {}
        },
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent
        },
        "processes": [
            info for info in [
                _get_process_info(proc, gulp_only)
                for proc in psutil.process_iter()
            ] if info is not None]
    }

    return JSendResponse.success(data=stats, req_id=req_id)


@router.get(
    "/trigger_gc",
    tags=["utility"],
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701278479259,
                        "req_id": "903546ff-c01e-4875-a585-d7fa34a0d237",
                        "data":  {
                            "before": {
                                "memory": {
                                    "rss_mb": 292.34375,
                                    "vms_mb": 1214.890625,
                                    "shared_mb": 5.4140625
                                },
                                "gc_stats": {
                                    "collections": [
                                        1,
                                        1,
                                        3
                                    ],
                                    "objects_tracked": 346601,
                                    "garbage": 0
                                }
                            },
                            "after": {
                                "memory": {
                                    "rss_mb": 292.34375,
                                    "vms_mb": 1214.890625,
                                    "shared_mb": 5.4140625
                                },
                                "gc_stats": {
                                    "collections": [
                                        1,
                                        0,
                                        0
                                    ],
                                    "objects_tracked": 346269,
                                    "garbage": 0
                                }
                            },
                            "delta": {
                                "rss_mb": 0.0,
                                "vms_mb": 0.0,
                                "shared_mb": 0.0,
                                "objects": 332
                            },
                            "collection_time_ms": 170.80650408752263
                        },
                    }
                }
            }
        }
    },
    response_model=JSendResponse,
    response_model_exclude_none=True,
    summary="trigger garbage collection.",
    description="""
- token needs `admin` permission.
- triggers garbage collection in the server main process.
""",
)
async def trigger_gc_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSONResponse:
    # baseline: 289
    # round 1: 388
    params = locals()
    ServerUtils.dump_params(params)
    async with GulpCollab.get_instance().session() as sess:
        await GulpUserSession.check_token(sess, token, GulpUserPermission.ADMIN)

    MutyLogger.get_instance().info("triggering garbage collection ...")
    d=muty.obj.trigger_gc_and_get_stats()
    return JSendResponse.success(data=d, req_id=req_id)


@router.get(
    "/plugin_list",
    tags=["plugin"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1734609216840,
                        "req_id": "8494de7b-e722-437a-a1c7-80341a0f3b27",
                        "data": [
                            {
                                "display_name": "csv",
                                "type": "ingestion",
                                "desc": "generic CSV file processor",
                                "filename": "csv",
                                "sigma_support": [],
                                "additional_parameters": [
                                    {
                                        "name": "delimiter",
                                        "type": "str",
                                        "default_value": ",",
                                        "desc": "delimiter for the CSV file",
                                        "required": False,
                                    }
                                ],
                                "depends_on": [],
                                "tags": [],
                                "version": "1.0",
                            },
                            {
                                "display_name": "raw",
                                "type": "ingestion",
                                "desc": "Raw events ingestion plugin",
                                "filename": "raw",
                                "sigma_support": [],
                                "additional_parameters": [],
                                "depends_on": [],
                                "tags": [],
                                "version": "1.0",
                            },
                            {
                                "display_name": "csv",
                                "type": "ingestion",
                                "desc": "stacked plugin on top of csv example",
                                "filename": "stacked_example",
                                "sigma_support": [],
                                "additional_parameters": [],
                                "depends_on": [],
                                "tags": [],
                                "version": "1.0",
                            },
                            {
                                "display_name": "win_evtx",
                                "type": "ingestion",
                                "desc": "Windows EVTX log file processor.",
                                "filename": "win_evtx",
                                "sigma_support": [
                                    {
                                        "backends": [
                                            {
                                                "name": "opensearch",
                                                "description": "OpenSearch Lucene backend for pySigma",
                                            }
                                        ],
                                        "pipelines": [
                                            {
                                                "name": "ecs_windows",
                                                "description": "ECS Mapping for windows event logs ingested with Winlogbeat or Gulp.",
                                            },
                                            {
                                                "name": "ecs_windows_old",
                                                "description": "ECS Mapping for windows event logs ingested with Winlogbeat<=6.x",
                                            },
                                        ],
                                        "output_formats": [
                                            {
                                                "name": "dsl_lucene",
                                                "description": "DSL with embedded Lucene queries.",
                                            }
                                        ],
                                    }
                                ],
                                "additional_parameters": [],
                                "depends_on": [],
                                "tags": [],
                                "version": "1.0",
                            },
                            {
                                "display_name": "extension_example",
                                "type": "extension",
                                "desc": "Extension example.",
                                "filename": "example",
                                "sigma_support": [],
                                "additional_parameters": [],
                                "depends_on": [],
                                "tags": [],
                                "version": "1.0",
                            },
                        ],
                    }
                }
            }
        }
    },
    summary="list available plugins.",
)
async def plugin_list_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSendResponse:
    ServerUtils.dump_params(locals())
    try:
        async with GulpCollab.get_instance().session() as sess:
            await GulpUserSession.check_token(sess, token, GulpUserPermission.READ)

            l = await GulpPluginBase.list()

            # turn to model_dump
            ll: list[dict] = []
            for p in l:
                ll.append(p.model_dump(exclude_none=True))
            return JSONResponse(JSendResponse.success(req_id=req_id, data=ll))
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.get(
    "/plugin_get",
    tags=["plugin"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701546711919,
                        "req_id": "ddfc094f-4a5b-4a23-ad1c-5d1428b57706",
                        "data": {
                            "filename": "win_evtx.py",
                            "path": "/opt/gulp/plugins/win_evtx.py",
                            "content": "base64 file content here",
                        },
                    }
                }
            }
        }
    },
    summary="get plugin content (i.e. for editing and reupload).",
    description="""
- token needs `edit` permission.
- file is read from the `PATH_PLUGINS_EXTRA` directory if set, either from the main plugins directory.
- file content is returned as base64.
""",
)
async def plugin_get_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    plugin: Annotated[
        str,
        Query(
            description='filename of the plugin to retrieve content for, i.e. "plugin.py", "paid/paid_plugin.py"'
        ),
    ],
    is_extension: Annotated[
        bool, Query(description="the plugin is an extension plugin")
    ] = False,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSendResponse:
    ServerUtils.dump_params(locals())

    try:
        async with GulpCollab.get_instance().session() as sess:
            await GulpUserSession.check_token(sess, token, GulpUserPermission.EDIT)
            file_path = GulpPluginBase.path_from_plugin(
                plugin, is_extension=is_extension, raise_if_not_found=True
            )

            # read file content
            f = await muty.file.read_file_async(file_path)
            filename = os.path.basename(file_path)

            return JSONResponse(
                JSendResponse.success(
                    req_id=req_id,
                    data={
                        "filename": filename,
                        "path": file_path,
                        "content": base64.b64encode(f).decode(),
                    },
                )
            )
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.delete(
    "/plugin_delete",
    tags=["plugin"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701266243057,
                        "req_id": "fb2759b8-b0a0-40cc-bc5b-b988f72255a8",
                        "data": {
                            "filename": "win_evtx.py",
                            "path": "/opt/gulp/plugins/win_evtx.py",
                        },
                    }
                }
            }
        }
    },
    summary="deletes an existing plugin file.",
    description="""
- token needs `edit` permission.
- plugin will be deleted from the `PATH_PLUGINS_EXTRA` directory, which must be set since the main plugins directly may not be writable.
""",
)
async def plugin_delete_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    plugin: Annotated[
        str,
        Query(
            description='filename of the plugin to be deleted, i.e. "plugin.py", "paid/paid_plugin.py"'
        ),
    ],
    is_extension: Annotated[
        bool, Query(description="the plugin is an extension plugin")
    ] = False,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSendResponse:
    ServerUtils.dump_params(locals())

    try:
        async with GulpCollab.get_instance().session() as sess:
            await GulpUserSession.check_token(sess, token, GulpUserPermission.EDIT)

            file_path = GulpPluginBase.path_from_plugin(
                plugin, is_extension=is_extension
            )

            # cannot delete base plugins (may be in a container)
            if GulpConfig.get_instance().path_plugins_default() in file_path:
                raise Exception(
                    "cannot delete plugin in base path: %s" % (file_path))

            # delete file
            await muty.file.delete_file_or_dir_async(file_path, ignore_errors=False)
            return JSONResponse(
                JSendResponse.success(
                    req_id=req_id, data={"filename": plugin, "path": file_path}
                )
            )
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.post(
    "/plugin_upload",
    tags=["plugin"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701266243057,
                        "req_id": "fb2759b8-b0a0-40cc-bc5b-b988f72255a8",
                        "data": {
                            "filename": "custom_plugin.py",
                            "path": "/opt/gulp/plugins/custom_plugin.py",
                        },
                    }
                }
            }
        }
    },
    summary="upload a .py/.pyc plugin file.",
    description="""
- token needs `edit` permission.
- to upload plugins, define `PATH_PLUGINS_EXTRA` environment variable since the default plugins directory is not writable.
""",
)
async def plugin_upload_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    plugin: Annotated[UploadFile, File(description="the plugin file to upload")],
    is_extension: Annotated[
        bool, Query(
            description="True if the plugin is an extension, False otherwise")
    ],
    filename: Annotated[
        str,
        Query(
            description='the filename to save the plugin as, i.e. "plugin.py", "paid/paid_plugin.py", defaults to the uploaded filename.'
        ),
    ] = None,
    allow_overwrite: Annotated[
        bool, Query(
            description="if set, will overwrite an existing plugin file.")
    ] = False,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSendResponse:
    params = locals()
    params["plugin"] = plugin.filename
    ServerUtils.dump_params(params)

    try:
        async with GulpCollab.get_instance().session() as sess:
            await GulpUserSession.check_token(sess, token, GulpUserPermission.EDIT)

            if not GulpConfig.get_instance().path_plugins_extra():
                raise Exception(
                    "to upload plugins, define PATH_PLUGINS_EXTRA.")

            await GulpUserSession.check_token(sess, token, GulpUserPermission.ADMIN)
            if not filename:
                # use default filename
                filename = os.path.basename(plugin.filename)

            # upload path
            extra_path = GulpConfig.get_instance().path_plugins_extra()
            file_path = muty.file.safe_path_join(extra_path, filename.lower())
            MutyLogger.get_instance().debug("saving plugin to: %s" % (file_path))

            if not allow_overwrite:
                # overwrite disabled
                if os.path.exists(file_path):
                    raise ObjectAlreadyExists(
                        "plugin %s already exists." % (filename))

            # ok, write file
            await muty.uploadfile.to_path(plugin, dest_dir=os.path.dirname(file_path))
            return JSONResponse(
                JSendResponse.success(
                    req_id=req_id,
                    data={
                        "filename": filename,
                        "path": file_path,
                    },
                )
            )
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.get(
    "/version",
    tags=["utility"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701266243057,
                        "req_id": "fb2759b8-b0a0-40cc-bc5b-b988f72255a8",
                        "data": {"version": "gulp v0.0.9 (muty v0.2)"},
                    }
                }
            }
        }
    },
    summary="get gULP version.",
)
async def get_version_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSendResponse:
    ServerUtils.dump_params(locals())

    try:
        async with GulpCollab.get_instance().session() as sess:
            await GulpUserSession.check_token(sess, token, GulpUserPermission.READ)

            return JSONResponse(
                JSendResponse.success(
                    req_id=req_id,
                    data={"version": GulpRestServer.get_instance().version_string()},
                )
            )
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.post(
    "/mapping_file_upload",
    tags=["mapping"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701266243057,
                        "req_id": "fb2759b8-b0a0-40cc-bc5b-b988f72255a8",
                        "data": {
                            "filename": "custom_mapping.json",
                            "path": "/opt/gulp/mapping_files/custom_mapping.json",
                        },
                    }
                }
            }
        }
    },
    summary="upload a JSON mapping file.",
    description="""
- token needs `edit` permission.
- to upload mapping files, define `PATH_MAPPING_FILES_EXTRA` environment variable since the default mapping files directory is not writable.
""",
)
async def mapping_file_upload_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    mapping_file: Annotated[
        UploadFile, File(description="the mapping json file")
    ] = None,
    allow_overwrite: Annotated[
        bool, Query(
            description="if set, will overwrite an existing mapping file.")
    ] = False,
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSendResponse:
    params = locals()
    params["mapping_file"] = mapping_file.filename
    ServerUtils.dump_params(params)

    try:
        async with GulpCollab.get_instance().session() as sess:
            await GulpUserSession.check_token(sess, token, [GulpUserPermission.EDIT])

        extra_path = GulpConfig.get_instance().path_mapping_files_extra()
        if not extra_path:
            raise Exception(
                "to upload mapping files, define PATH_MAPPING_FILES_EXTRA.")

        # load file
        filename: str = os.path.basename(mapping_file.filename)
        content: dict = None
        try:
            # check if the file is a valid mapping file
            content = json.loads(mapping_file.file.read())
            GulpMappingFile.model_validate(content)
        except Exception as ex:
            # not a valid json or GulpMappingFile
            raise ex

        if not filename.lower().endswith(".json"):
            filename.append(".json")

        # upload path
        file_path = muty.file.safe_path_join(extra_path, filename.lower())
        MutyLogger.get_instance().debug("saving mapping file to: %s" % (file_path))

        if not allow_overwrite:
            # overwrite disabled
            if os.path.exists(file_path):
                raise ObjectAlreadyExists(
                    "mapping file %s already exists." % (file_path)
                )

        # ok, write file
        await muty.file.write_file_async(
            file_path, json.dumps(content, indent=2).encode()
        )
        return JSONResponse(
            JSendResponse.success(
                req_id=req_id, data={"filename": filename, "path": file_path}
            )
        )
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.get(
    "/mapping_file_list",
    tags=["mapping"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1735294441540,
                        "req_id": "test_req",
                        "data": [
                            {
                                "metadata": {"plugin": ["splunk.py"]},
                                "filename": "splunk.json",
                                "path": "/opt/gulp/mapping_files/splunk.json",
                                "mapping_ids": ["splunk"],
                            },
                            {
                                "metadata": {"plugin": ["csv.py"]},
                                "filename": "mftecmd_csv.json",
                                "path": "/opt/gulp/mapping_files/mftecmd_csv.json",
                                "mapping_ids": ["record", "boot", "j", "sds"],
                            },
                            {
                                "metadata": {"plugin": ["win_evtx.py"]},
                                "filename": "windows.json",
                                "path": "/opt/gulp/mapping_files/windows.json",
                                "mapping_ids": ["windows"],
                            },
                        ],
                    }
                }
            }
        }
    },
    summary="lists available mapping files.",
)
async def mapping_file_list_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSendResponse:
    ServerUtils.dump_params(locals())

    def _exists(d: list[dict], filename: str) -> bool:
        for f in d:
            if f["filename"].lower() == filename.lower():
                return True
        return False

    async def _list_mapping_files_internal(path: str, d: list[dict]) -> None:
        """
        lists mapping files in path and append to d
        """
        MutyLogger.get_instance().info("listing mapping files in %s" % (path))
        if not path:
            return

        files = await muty.file.list_directory_async(path)

        # for each file, get metadata and mapping_ids
        for f in files:
            if not f.lower().endswith(".json"):
                continue

            filename = os.path.basename(f)
            if _exists(d, filename):
                MutyLogger.get_instance().warning(
                    "skipping mapping file %s (already exists)" % (f)
                )
                continue

            # read file
            content = await muty.file.read_file_async(f)
            js = json.loads(content)

            # get metadata
            mtd = js.get("metadata", {})

            # get mapping_id for each mapping
            mappings: dict = js.get("mappings", {})
            mapping_ids = list(str(key) for key in mappings.keys())

            d.append(
                {
                    "metadata": mtd,
                    "filename": filename.lower(),
                    "path": f,
                    "mapping_ids": mapping_ids,
                }
            )

    try:
        async with GulpCollab.get_instance().session() as sess:
            await GulpUserSession.check_token(sess, token)

        d: list[dict] = []
        default_path = GulpConfig.get_instance().path_mapping_files_default()
        extra_path = GulpConfig.get_instance().path_mapping_files_extra()

        # extra_path first
        await _list_mapping_files_internal(extra_path, d)

        # then default
        await _list_mapping_files_internal(default_path, d)

        return JSONResponse(JSendResponse.success(req_id=req_id, data=d))
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex) from ex


@router.get(
    "/mapping_file_get",
    tags=["mapping"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701266243057,
                        "req_id": "fb2759b8-b0a0-40cc-bc5b-b988f72255a8",
                        "data": {
                            "filename": "windows.json",
                            "path": "/opt/gulp/mapping_files/windows.json",
                            "content": "base64 file content",
                        },
                    }
                }
            }
        }
    },
    summary="get a mapping file (i.e. for editing and reupload).",
    description="""
- token needs `edit` permission.
- file is read from the `gulp/mapping_files` directory (which can be overridden by `PATH_MAPPING_FILES_EXTRA` environment variable).    
""",
)
async def mapping_file_get_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    mapping_file: Annotated[
        str, Query(description='the mapping file to get (i.e. "windows.json")')
    ],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSendResponse:
    ServerUtils.dump_params(locals())

    try:
        async with GulpCollab.get_instance().session() as sess:
            await GulpUserSession.check_token(sess, token, GulpUserPermission.EDIT)

        file_path = GulpConfig.get_instance().build_mapping_file_path(mapping_file)

        # read file content
        f = await muty.file.read_file_async(file_path)
        filename = os.path.basename(file_path)
        return JSONResponse(
            JSendResponse.success(
                req_id=req_id,
                data={
                    "filename": filename,
                    "path": file_path,
                    "content": base64.b64encode(f).decode(),
                },
            )
        )
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex, status_code=404) from ex


@router.delete(
    "/mapping_file_delete",
    tags=["mapping"],
    response_model=JSendResponse,
    response_model_exclude_none=True,
    responses={
        200: {
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "timestamp_msec": 1701266243057,
                        "req_id": "fb2759b8-b0a0-40cc-bc5b-b988f72255a8",
                        "data": {
                            "filename": "windows.json",
                            "path": "/opt/gulp/mapping_files/windows.json",
                        },
                    }
                }
            }
        }
    },
    summary="deletes an existing mapping file.",
    description="""
- token needs `edit` permission.
- file will be deleted from the `gulp/mapping_files` directory (which can be overridden by `PATH_MAPPING_FILES` environment variable).
""",
)
async def mapping_file_delete_handler(
    token: Annotated[str, Depends(APIDependencies.param_token)],
    mapping_file: Annotated[
        str, Query(description='the mapping file to delete (i.e. "windows.json")')
    ],
    req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
) -> JSendResponse:
    ServerUtils.dump_params(locals())

    try:
        async with GulpCollab.get_instance().session() as sess:
            await GulpUserSession.check_token(sess, token, GulpUserPermission.EDIT)

        file_path = GulpConfig.get_instance().build_mapping_file_path(mapping_file)

        # cannot delete base plugins (may be in a container)
        if GulpConfig.get_instance().path_mapping_files_default() in file_path:
            raise Exception(
                "cannot delete mapping file in base path: %s" % (file_path))

        # delete file
        await muty.file.delete_file_or_dir_async(file_path, ignore_errors=False)
        return JSONResponse(
            JSendResponse.success(
                req_id=req_id, data={
                    "filename": mapping_file, "path": file_path}
            )
        )
    except Exception as ex:
        raise JSendException(req_id=req_id, ex=ex, status_code=404) from ex
