from typing import Any, override
import muty.os
import muty.string
import muty.xml
import muty.time


from gulp.api.collab.stats import GulpRequestStats
from gulp.api.collab.structs import GulpRequestStatus
from gulp.api.mapping.models import GulpMapping
from gulp.api.opensearch.filters import GulpIngestionFilter
from gulp.plugin import GulpPluginType
from gulp.plugin import GulpPluginBase
from sqlalchemy.ext.asyncio import AsyncSession

from gulp.structs import GulpPluginParameters


class Plugin(GulpPluginBase):
    """
    linux auth.log plugin stacked over the REGEX plugin
    """

    def type(self) -> list[GulpPluginType]:
        return [GulpPluginType.INGESTION]

    @override
    def desc(self) -> str:
        return """linux auth.log plugin stacked over the REGEX plugin"""

    def display_name(self) -> str:
        return "lin_auth"

    @override
    def depends_on(self) -> list[str]:
        return ["regex"]

    @override
    async def _record_to_gulp_document(
        self, record: dict, record_idx: int, **kwargs
    ) -> dict:
        ts = muty.time.string_to_nanos_from_unix_epoch(record["gulp.unmapped.timestamp"])
        
        record["agent.type"] = self.display_name() #override agent.type
        record["@timestamp"] = muty.time.number_to_iso8601(ts)
        record["gulp.timestamp"] = ts
        record["event.code"] = muty.crypto.hash_xxh64(record["gulp.unmapped.process"])

        #sshd logs should be treated differently as we can attempt to extract ip information
        if record.get("gulp.unmapped.process", "").lower() == "sshd":
            info = record.get("gulp.unmapped.info", "")

            #TODO: something like this? 
            # r"^Connection from (?<ip_src>([0-9]+.)+) port (?<src_port>([0-9]+)) on (?<ip_dst>([0-9]+.)+) port (?<dst_port>([0-9]+)).*$"
            # need to verify the format is always the same no matter the version of ssh (also case and separators)
            record["source.ip"] = ""
            record["source.port"] = ""
            record["destination.ip"] = ""
            record["destination.port"] = ""
            
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
            lower = await self.setup_stacked_plugin("regex")
        except Exception as ex:
            await self._source_failed(ex)
            return GulpRequestStatus.FAILED

        regex = r"".join([r"^(?P<timestamp>(?P<month>\S{3})?\s",
                r"{1,2}(?P<day>\S+)\s",
                r"(?P<time>\S+))\s",
                r"(?P<hostname>\S+)\s"
                r"(?P<process>.+?(?=\[)|.+?(?=))[^a-zA-Z0-9]",
                r"(?P<pid>\d{1,7}|)[^a-zA-Z0-9]{1,3}(?P<info>.*)$"
            ]
        )
        
        plugin_params.model_extra["regex"] = regex

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


