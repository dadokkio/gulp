import asyncio
from typing import Annotated

import muty.file
import muty.jsend
import muty.list
import muty.log
import muty.os
import muty.string
import muty.uploadfile
from fastapi import Header, Query, Depends
from muty.jsend import JSendException, JSendResponse
from muty.log import MutyLogger

from gulp.api.collab.stats import GulpIngestionStats
from gulp.api.collab.user_session import GulpUserSession
from gulp.api.collab_api import GulpCollab
from gulp.api.rest.server_utils import ServerUtils
from gulp.api.rest.structs import APIDependencies
from gulp.api.rest_api import GulpRestServer
from gulp.api.ws_api import GulpSharedWsQueue, GulpWsQueueDataType
from gulp.plugin import GulpPluginBase, GulpPluginType
from gulp.process import GulpProcess

"""
# extension plugins

## loading

extension plugins are automatically loaded at startup from `PLUGIN_DIR/extension`.

## internals

- they may extend api through `rest_api.fastapi_app().add_api_route()`.
- `their init runs in the MAIN process context`
- they may use aiopool and process_executor from rest_api as usual, **as long as they are run from the MAIN process (in this example, "example_task" is running in the MAIN process)**.

"""


class Plugin(GulpPluginBase):
    def __init__(
        self,
        path: str,
        pickled: bool = False,
        **kwargs,
    ) -> None:

        # extensions must support pickling
        super().__init__(path, pickled, **kwargs)
        MutyLogger.get_instance().debug(
            "path=%s, pickled=%r, kwargs=%s" % (path, pickled, kwargs)
        )

        # add api routes for this plugin
        if not self._pickled:
            # in the first init, add api routes (we are in the MAIN process here)
            self._add_api_routes()
            MutyLogger.get_instance().debug(
                "%s extension plugin initialized" % (self.display_name)
            )
        else:
            # in the re-init, we are in the worker process here
            MutyLogger.get_instance().debug(
                "%s extension plugin re-initialized" % self.display_name()
            )

    async def _run_in_worker(
        self,
        user_id: str,
        operation_id: str,
        ws_id: str,
        req_id: str,
        **kwargs,
    ) -> dict:
        MutyLogger.get_instance().error(
            "IN WORKER PROCESS, for user_id=%s, operation_id=%s, ws_id=%s, req_id=%s"
            % (user_id, operation_id, ws_id, req_id)
        )
        GulpSharedWsQueue.get_instance().put(
            GulpWsQueueDataType.COLLAB_UPDATE,
            req_id=req_id,
            ws_id=ws_id,
            user_id="dummy",
            data={"hello": "world"},
        )
        return {"done": True}

    async def _example_task(
        self,
        user_id: str,
        operation_id: str,
        context_id: str,
        ws_id: str,
        req_id: str,
        **kwargs,
    ):
        MutyLogger.get_instance().error(
            "IN MAIN PROCESS, for user_id=%s, operation_id=%s, context_id=%s, ws_id=%s, req_id=%s"
            % (user_id, operation_id, context_id, ws_id, req_id)
        )
        # create an example stats
        async with GulpCollab.get_instance().session() as sess:
            try:
                await GulpIngestionStats.create(
                    sess,
                    user_id,
                    req_id,
                    ws_id=ws_id,
                    operation_id=operation_id,
                    context_id=context_id,
                    source_total=33,
                )
            except Exception as ex:
                raise JSendException(req_id=req_id, ex=ex) from ex

        # spawn coro in worker process
        tasks = []
        MutyLogger.get_instance().debug(
            "spawning process for extension example for user_id=%s, operation_id=%s, context_id=%s, ws_id=%s, req_id=%s"
            % (user_id, operation_id, context_id, ws_id, req_id)
        )
        try:
            tasks.append(
                GulpProcess.get_instance().process_pool.apply(
                    self._run_in_worker,
                    (user_id, operation_id, context_id, ws_id, req_id),
                )
            )

            # and async wait for it to finish
            res = await asyncio.gather(*tasks, return_exceptions=True)
            MutyLogger.get_instance().error("extension example done: %s" % res)

        except Exception as ex:
            MutyLogger.get_instance().exception(ex)
            raise JSendException(req_id=req_id, ex=ex) from ex

    def _add_api_routes(self):
        # add /example_extension API
        GulpRestServer.get_instance().add_api_route(
            "/example_extension",
            self.example_extension_handler,
            methods=["PUT"],
            response_model=JSendResponse,
            response_model_exclude_none=True,
            tags=["extensions"],
            responses={
                200: {
                    "content": {
                        "application/json": {
                            "example": {
                                "status": "success",
                                "timestamp_msec": 1701278479259,
                                "req_id": "903546ff-c01e-4875-a585-d7fa34a0d237",
                                "data": {"result": "example"},
                            }
                        }
                    }
                }
            },
            summary="just an example.",
        )

    async def example_extension_handler(
        self,
        token: Annotated[str, Depends(APIDependencies.param_token)],
        operation_id: Annotated[str, Depends(APIDependencies.param_operation_id)],
        context_id: Annotated[str, Depends(APIDependencies.param_context_id)],
        ws_id: Annotated[str, Depends(APIDependencies.param_ws_id)],
        req_id: Annotated[str, Depends(APIDependencies.ensure_req_id)] = None,
    ) -> JSendResponse:
        req_id = ServerUtils.ensure_req_id(req_id)

        try:
            session = await GulpUserSession.check_token(token)

            # spawn coroutine in the main process, will run asap
            coro = self._example_task(
                session.user_id, operation_id, context_id, ws_id, req_id
            )
            await GulpProcess.get_instance().coro_pool.spawn(coro)
            return muty.jsend.pending_jsend(req_id=req_id)
        except Exception as ex:
            raise JSendException(req_id=req_id, ex=ex) from ex

    def desc(self) -> str:
        return "Extension example."

    def type(self) -> GulpPluginType:
        return GulpPluginType.EXTENSION

    def display_name(self) -> str:
        return "extension_example"

    def version(self) -> str:
        return "1.0"
