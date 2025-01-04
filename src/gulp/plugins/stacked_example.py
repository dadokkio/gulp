from typing import Any, override

import aiofiles
import muty.dict
import muty.os
import muty.string
import muty.xml
from sqlalchemy.ext.asyncio import AsyncSession

from gulp.api.collab.stats import GulpRequestStats, RequestCanceledError
from gulp.api.collab.structs import GulpRequestStatus
from gulp.api.opensearch.filters import GulpIngestionFilter
from gulp.api.opensearch.structs import GulpDocument
from gulp.plugin import GulpPluginBase, GulpPluginType
from gulp.structs import GulpPluginCustomParameter, GulpPluginParameters

try:
    from aiocsv import AsyncDictReader
except Exception:
    muty.os.install_package("aiocsv")
    from aiocsv import AsyncDictReader


class Plugin(GulpPluginBase):
    def type(self) -> list[GulpPluginType]:
        return [GulpPluginType.INGESTION]

    def display_name(self) -> str:
        return "stacked_example"

    @override
    def desc(self) -> str:
        return """stacked plugin on top of csv example"""

    @override
    async def _enrich_documents_chunk(self, docs: list[dict], data: Any) -> list[dict]:
        for doc in docs:
            doc["enriched"] = True
        return docs

    @override
    async def _record_to_gulp_document(
        self, record: dict, record_idx: int, data: Any
    ) -> dict:

        # MutyLogger.get_instance().debug("record: %s" % record)
        # tweak event duration ...
        record["event.duration"] = 9999
        return record

    async def ingest_file(
        self,
        sess: AsyncSession,
        stats: GulpRequestStats,
        user_id: str,
        req_id: str,
        ws_id: str,
        index: str,
        operation_id: str,
        context_id: str,
        source_id: str,
        file_path: str,
        original_file_path: str = None,
        plugin_params: GulpPluginParameters = None,
        flt: GulpIngestionFilter = None,
    ) -> GulpRequestStatus:

        # set as stacked
        try:
            lower = await self.setup_stacked_plugin("csv")
        except Exception as ex:
            await self._source_failed(ex)
            return GulpRequestStatus.FAILED

        # call lower plugin, which in turn will call our record_to_gulp_document after its own processing
        res = await lower.ingest_file(
            sess=sess,
            stats=stats,
            user_id=user_id,
            req_id=req_id,
            ws_id=ws_id,
            index=index,
            operation_id=operation_id,
            context_id=context_id,
            source_id=source_id,
            file_path=file_path,
            original_file_path=original_file_path,
            plugin_params=plugin_params,
            flt=flt,
        )
        await lower.unload()
        return res
