from gulp.api.opensearch.filters import GulpIngestionFilter
from gulp.structs import GulpPluginParameters
from tests.api.common import GulpAPICommon
import os
import json
from typing import Dict, Optional


class GulpAPIIngest:
    """Bindings to call gulp's ingest related API endpoints"""

    @staticmethod
    async def ingest_file(
        token: str,
        file_path: str,
        operation_id: str,
        context_name: str,
        index: str,
        plugin: str,
        file_total: int = 1,
        flt: Optional[GulpIngestionFilter] = None,
        plugin_params: Optional[GulpPluginParameters] = None,
        restart_from: int = 0,
        expected_status: int = 200,
    ) -> dict:
        api_common = GulpAPICommon.get_instance()
        file_size = os.path.getsize(file_path)

        params = {
            "operation_id": operation_id,
            "context_name": context_name,
            "index": index,
            "plugin": plugin,
            "ws_id": api_common.ws_id,
            "req_id": api_common.req_id,
            "file_total": file_total,
        }

        payload = {
            "flt": flt.model_dump(exclude_none=True) if flt else {},
            "plugin_params": plugin_params.model_dump(exclude_none=True) if plugin_params else {},
            "original_file_path": file_path,
        }

        files = {
            "payload": ("payload.json", json.dumps(payload), "application/json"),
            "f": (
                os.path.basename(file_path),
                open(file_path, "rb"),
                "application/octet-stream",
            ),
        }

        headers = {"size": str(file_size), "continue_offset": str(restart_from)}

        return await api_common.make_request(
            "POST",
            "ingest_file",
            params=params,
            token=token,
            files=files,
            headers=headers,
            expected_status=expected_status,
        )

    @staticmethod
    async def ingest_zip(
        token: str,
        file_path: str,
        operation_id: str,
        context_name: str,
        index: str,
        flt: Optional[GulpIngestionFilter] = None,
        restart_from: int = 0,
        expected_status: int = 200,
    ) -> dict:
        """Ingest a ZIP archive containing files to process"""
        api_common = GulpAPICommon.get_instance()
        file_size = os.path.getsize(file_path)

        params = {
            "operation_id": operation_id,
            "context_name": context_name,
            "index": index,
            "ws_id": api_common.ws_id,
            "req_id": api_common.req_id,
        }

        payload = {"flt": flt.model_dump(exclude_none=True) if flt else {}}

        files = {
            "payload": ("payload.json", json.dumps(payload), "application/json"),
            "f": (
                os.path.basename(file_path),
                open(file_path, "rb"),
                "application/zip",
            ),
        }

        headers = {"size": str(file_size), "continue_offset": str(restart_from)}

        return await api_common.make_request(
            "POST",
            "ingest_zip",
            params=params,
            token=token,
            files=files,
            headers=headers,
            expected_status=expected_status,
        )

    @staticmethod
    async def ingest_raw(
        token: str,
        raw_data: Dict,
        operation_id: str,
        context_name: str,
        index: str,
        plugin: str = None,
        plugin_params: Optional[GulpPluginParameters] = None,
        flt: Optional[GulpIngestionFilter] = None,
        source: str = None,
        expected_status: int = 200,
    ) -> dict:
        """Ingest raw data using the raw plugin"""
        api_common = GulpAPICommon.get_instance()

        params = {
            "operation_id": operation_id,
            "context_name": context_name,
            "source": source or "raw",
            "index": index,
            "plugin": plugin or "raw",
            "ws_id": api_common.ws_id,
            "req_id": api_common.req_id,
        }

        body = {
            "flt": flt.model_dump(exclude_none=True) if flt else {},
            "chunk": raw_data,
            "plugin_params": plugin_params.model_dump(exclude_none=True) if plugin_params else {},
        }

        return await api_common.make_request(
            "POST",
            "ingest_raw",
            params=params,
            body=body,
            token=token,
            expected_status=expected_status,
        )
