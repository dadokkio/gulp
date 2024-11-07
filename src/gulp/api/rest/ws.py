import asyncio
from concurrent.futures import ThreadPoolExecutor
from enum import StrEnum
from queue import Empty, Queue
from typing import Optional, override

import muty.crypto
import muty.file
import muty.jsend
import muty.list
import muty.log
import muty.os
import muty.string
import muty.time
import muty.uploadfile
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from starlette.endpoints import WebSocketEndpoint

from gulp.api.collab.user_session import GulpUserSession


import gulp.api.rest_api as rest_api
import gulp.config as config
from gulp.api.collab.structs import GulpUserPermission
from gulp.utils import GulpLogger

_app: APIRouter = APIRouter()

class WsQueueDataType(StrEnum):
    """
    The type of data into the websocket queue.
    """

    STATS_UPDATE = "stats_update"
    COLLAB_UPDATE = "collab_update"
    QUERY_DONE = "query_done"
    REBASE_DONE = "rebase_done"
    CHUNK = "chunk"


class WsParameters(BaseModel):
    """
    Parameters for the websocket.
    """
    token: str = Field(..., description="user token")
    ws_id: str = Field(..., description="The WebSocket ID.")
    operation: Optional[list[str]] = Field(
        None,
        description="The operation/s this websocket is registered to receive data for, defaults to None(=all).",
    )
    type: Optional[list[WsQueueDataType]] = Field(
        None,
        description="The WsData.type this websocket is registered to receive, defaults to None(=all).",
    )


class WsData(BaseModel):
    """
    data carried by the websocket
    """
    timestamp: int = Field(..., description="The timestamp of the data.")
    type: WsQueueDataType = Field(
        ..., description="The type of data carried by the websocket."
    )
    user: str = Field(..., description="The user who issued the request.")
    ws_id: str = Field(..., description="The WebSocket ID.")
    req_id: Optional[str] = Field(None, description="The request ID.")
    operation: Optional[str] = Field(None, description="The operation this data belongs to.")
    private: Optional[bool] = Field(
        False,
        description="If the data is private(=only ws=ws_id can receive it).",
    )
    data: Optional[dict] = Field(None, description="The data carried by the websocket.")

class ConnectedSocket():
    """ 
    Represents a connected websocket.
    """
    def __init__(self, ws: WebSocket, ws_id: str, type: list[WsQueueDataType]=None, operation: list[str]=None):
        """
        Initializes the ConnectedSocket object.

        Args:
            ws (WebSocket): The WebSocket object.
            ws_id (str): The WebSocket ID.
            type (list[WsQueueDataType], optional): The types of data this websocket is interested in. Defaults to None (all).
            operation (list[str], optional): The operations this websocket is interested in. Defaults to None (all).
        """
        self.ws = ws
        self.ws_id = ws_id
        self.type = type
        self.operation = operation

        # each socket has its own asyncio queue
        self.q = asyncio.Queue()

    def __str__(self):
        return f"ConnectedSocket(ws_id={self.ws_id}, registered_types={self.type}, registered_operations={self.operation})"
   
class GulpConnectedSockets():
    """
    singleton class to hold all connected sockets
    """
    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, "_instance"):
            cls._instance = super().__new__(cls)
        return cls._instance
    def __init__(self):
        if not hasattr(self, "_initialized"):
            self._initialized = True
            self._sockets: dict[str, ConnectedSocket] = {}
    
    def add(self, ws: WebSocket, ws_id: str, type: list[WsQueueDataType]=None, operation: list[str]=None) -> ConnectedSocket:   
        """
        Adds a websocket to the connected sockets list.

        Args:
            ws (WebSocket): The WebSocket object.
            ws_id (str): The WebSocket ID.
            type (list[WsQueueDataType], optional): The types of data this websocket is interested in. Defaults to None (all)
            operation (list[str], optional): The operations this websocket is interested in. Defaults to None (all)

        Returns:
            ConnectedSocket: The ConnectedSocket object.
        """
        ws = ConnectedSocket(ws=ws, ws_id=ws_id, type=type, operation=operation)
        self._sockets[str(id(ws))] = ws
        GulpLogger().debug(f"added connected ws {id(ws)}: {ws}")
        return ws
    
    async def remove(self, ws: WebSocket, flush: bool=True) -> None:
        """
        Removes a websocket from the connected sockets list

        Args:
            ws (WebSocket): The WebSocket object.
            flush (bool, optional): If the queue should be flushed. Defaults to True.

        """
        id_str = str(id(ws))
        cws = self._sockets.get(id_str, None)
        if cws is None:
            GulpLogger().warning(f"no websocket found for ws_id={id_str}")
            return

        # flush queue first
        if flush:
            q = cws.q
            while q.qsize() != 0:
                try:
                    q.get_nowait()
                    q.task_done()
                except Exception:
                    pass

            await q.join()
            GulpLogger().debug(f"queue flush done for ws id={id_str}")

        GulpLogger().debug(f"removed connected ws, id={id_str}")
        del self._sockets[id_str]

    def find(self, ws_id: str) -> ConnectedSocket:
        """
        Finds a ConnectedSocket object by its ID.

        Args:
            ws_id (str): The WebSocket ID.

        Returns:
            ConnectedSocket: The ConnectedSocket object or None if not found.
        """
        for _, v in self._sockets.items():
            if v.ws_id == ws_id:
                return v
            
        GulpLogger().warning(f"no websocket found for ws_id={ws_id}")
        return None
    
    async def wait_all_close(self) -> None:
        """
        Waits for all active websockets to close.
        """
        while len(self._sockets) > 0:
            GulpLogger().debug("waiting for active websockets to close ...")
            await asyncio.sleep(1)
        GulpLogger().debug("all active websockets closed!")

    async def close_all(self) -> None:
        """
        Closes all active websockets.
        """
        for _, cws in self._sockets.items():
            await self.remove(cws.ws, flush=True)
        GulpLogger().debug("all active websockets closed!")
    
    async def broadcast_data(self, d: WsData):
        """
        broadcasts data to all connected websockets

        Args:
            d (WsData): The data to broadcast.
        """
        for _, cws in self._sockets.items():
            if cws.type:
                # check types
                if not d.type in cws.type:
                    GulpLogger().warning(
                        "skipping entry type=%s for ws_id=%s, cws.types=%s"
                        % (d.type, cws.ws_id, cws.type)
                    )
                    continue
            if cws.operation:
                # check operation/s
                if not d.operation in cws.operation:
                    GulpLogger().warning(
                        "skipping entry type=%s for ws_id=%s, cws.operation=%s"
                        % (d.type, cws.ws_id, cws.operation)
                    )
                    continue

                if cws.ws_id == d.ws_id:
                    # always relay to the ws async queue for the target websocket
                    await cws.q.put(d)
                else:
                    # not the target websocket
                    if d.private:
                        # do not broadcast private data
                        GulpLogger().warning(
                            "skipping entry type=%s for ws_id=%s, private=True"
                            % (d.type, cws.ws_id)
                        )
                        continue

                    # only relay collab updates to other ws
                    if d.type not in [WsQueueDataType.COLLAB_UPDATE]:
                        continue

                    await cws.q.put(d)

class GulpSharedWsDataQueue():
    """
    singleton class to manage adding data to the shared websocket queue
    """
    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, "_instance"):
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, "_initialized"):
            self._initialized = True
            self._shared_q: Queue = None

    def init_in_worker_process(self, q: Queue):
        """
        Initializes the shared queue in a worker process.

        Args:
            q (Queue): The shared queue from worker's process initializer
        """
        self._shared_q = q

    def init_in_main_process(self):
        """
        Initializes the shared queue in the main process.
        """
        # in the main process, initialize the shared queue and start the asyncio queue fill task
        self._shared_q: Queue = Queue()
        asyncio.create_task(self._fill_ws_queues_from_shared_queue())


    async def _fill_ws_queues_from_shared_queue(self):
        """

        runs continously (in the main process) to walk through the queued data in the multiprocessing shared queue and fill each connected websocket asyncio queue
        """

        # uses an executor to run the blocking get() call in a separate thread
        GulpLogger().debug("starting asyncio queue fill task ...")
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as pool:
            while True:
                if rest_api.is_shutdown():
                    break

                # GulpLogger().debug("running ws_q.get in executor ...")
                try:
                    # get a WsData entry from the shared multiprocessing queue
                    d: dict = await loop.run_in_executor(pool, self._shared_q.get, True, 1)
                    self._shared_q.task_done()
                    entry = WsData.model_validate(d)

                    # find the websocket associated with this entry
                    cws = GulpConnectedSockets().find(entry.ws_id)
                    if not cws:
                        # no websocket found for this entry, skip (this WsData entry will be lost)
                        continue
                    
                    # broadcast
                    await GulpConnectedSockets().broadcast_data(entry)

                except Empty:
                    # let's not busy wait...
                    await asyncio.sleep(1)
                    continue

    def close(self) -> None:
        """
        Closes the shared multiprocessing queue (flushes it first).

        Returns:
            None
        """
        # flush queue first
        while self._shared_q.qsize() != 0:
            try:
                self._shared_q.get_nowait()
                self._shared_q.task_done()
            except Exception:
                pass

        self._shared_q.join()


    def add_data(self,
        type: WsQueueDataType,
        user: str,
        ws_id: str,
        operation: str=None,
        req_id: str = None,
        data: dict = None,
        private: bool = False) -> None:
        """
        Adds data to the shared queue.

        Args:
            type (WsQueueDataType): The type of data.
            user (str): The user.
            ws_id (str): The WebSocket ID.
            operation (str, optional): The operation.
            req_id (str, optional): The request ID. Defaults to None.
            data (dict, optional): The data. Defaults to None.
            private (bool, optional): If the data is private. Defaults to False.        
        """
        wsd = WsData(
            timestamp=muty.time.now_msec(),
            type=type,
            operation=operation,
            user=user,
            ws_id=ws_id,
            req_id=req_id,
            private=private,
            data=data,
        )
        GulpLogger().debug("adding entry type=%s to ws_id=%s queue..." % (wsd.type, wsd.ws_id))
        # TODO: try and see if it works without serializing...
        self._shared_q.put(wsd.model_dump())


@_app.websocket_route("/ws")
class WebSocketHandler(WebSocketEndpoint):
    """
    the websocket protocol is really simple:

    1. client sends a json request { "token": ..., "ws_id": ...}
    2. server checks the token and ws_id, and accepts the connection
    3. server sends messages to the client with the same ws_id (plus broadcasting CollabObj objects to the other connected websockets)
    """
    @override
    def __init__(self, scope, receive, send) -> None:
        self._ws: ConnectedSocket = None
        self._cancel_event: asyncio.Event = None
        self._consumer_task: asyncio.Task = None

        super().__init__(scope, receive, send)

    @override
    async def on_connect(self, websocket: WebSocket) -> None:
        GulpLogger().debug("awaiting accept ...")
        super().on_connect(websocket)

        try:
            js = await websocket.receive_json()
            params = WsParameters.model_validate_json(js)
            await GulpUserSession.check_token_permission(params.token, GulpUserPermission.READ)
        except Exception as ex:
            GulpLogger().error("ws rejected: %s" % (ex))
            return

        # connection is ok
        GulpLogger().debug("ws accepted for ws_id=%s!" % (params.ws_id))
        ws = GulpConnectedSockets().add(websocket, params.ws_id, params.type, params.operation)
        self._ws = ws
        self._cancel_event = asyncio.Event()

        # start the consumer task to send data to the websocket as it arrives in the queue (via calls GulpSharedWsDataQueue.add_data())
        self._consumer_task = asyncio.create_task(self.send_data_loop())
        GulpLogger().debug("created consumer task for ws_id=%s!" % (params.ws_id))

    @override
    async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
        GulpLogger().debug("on_disconnect, close_code=%d" % (close_code))
        if self._consumer_task is not None:
            GulpLogger().debug("canceling consumer task ...")
            self._consumer_task.cancel()

        # remove websocket from active list and close it
        await GulpConnectedSockets().remove(websocket)

    async def _read_items(self, q: asyncio.Queue):
        """
        Reads WsData items from the websocket's asyncio queue.

        Args:
            q (asyncio.Queue): The asyncio queue.

        Yields:
            Any: The item read from the queue.            
        """
        # GulpLogger().debug("reading items from queue ...")
        while True:
            item = await q.get()
            q.task_done()
            yield item

    async def send_data_loop(self) -> None:
        """
        Sends data to the websocket as it arrives, infinitely looping until the websocket disconnects.

        Raises:
            WebSocketDisconnect: If the websocket disconnects.
        """
        GulpLogger().debug('starting ws "%s" loop ...' % (self._ws.ws_id))
        async for item in self._read_items(self._ws.q):
            try:
                # send
                await self._ws.ws.send_json(item)

                # rate limit
                ws_delay = config.ws_rate_limit_delay()
                await asyncio.sleep(ws_delay)

            except WebSocketDisconnect as ex:
                GulpLogger().exception("ws disconnected: %s" % (ex))
                break
            except Exception as ex:
                GulpLogger().exception("ws error: %s" % (ex))
                break
            except asyncio.CancelledError as ex:
                GulpLogger().exception("ws cancelled: %s" % (ex))
                break

def router() -> APIRouter:
    """
    Returns this module api-router, to add it to the main router

    Returns:
        APIRouter: The APIRouter instance
    """
    global _app
    return _app
