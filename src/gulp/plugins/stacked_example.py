from typing import override

import aiofiles
import muty.dict
import muty.os
import muty.string
import muty.xml

from gulp.api.collab.stats import GulpIngestionStats, RequestCanceledError
from gulp.api.collab.structs import GulpRequestStatus
from gulp.api.opensearch.filters import GulpIngestionFilter
from gulp.api.opensearch.structs import GulpDocument
from gulp.plugin import GulpPluginBase, GulpPluginType
from gulp.structs import GulpPluginAdditionalParameter, GulpPluginParameters

try:
    from aiocsv import AsyncDictReader
except Exception:
    muty.os.install_package("aiocsv")
    from aiocsv import AsyncDictReader


class Plugin(GulpPluginBase):
    """
    CSV generic file processor

    the csv plugin may ingest any CSV file itself, but it is also used as a base plugin for other plugins (in "stacked" mode).

    ### standalone mode

    when used by itself, it is enough to ingest a CSV file with the default settings (no extra parameters needed).

    NOTE: since each document must have a "@timestamp", a GulpMapping must be set with a "timestamp_field" set in the plugin_params.

    ~~~bash
    # all CSV field will result in "gulp.unmapped.*" fields, timestamp will be set from "UpdateTimestamp" field
    TEST_PLUGIN_PARAMS='{"timestamp_field": "UpdateTimestamp"}' TEST_PLUGIN=csv ./test_scripts/test_ingest.sh -p ./samples/mftecmd/sample_j.csv

    # use a mapping file
    # a mapping file may hold more than one mapping definition with its own options (as defined in helpers.get_mapping_from_file())
    TEST_PLUGIN_PARAMS='{"mapping_file": "mftecmd_csv.json", "mapping_id": "j"}' TEST_PLUGIN=csv ./test_scripts/test_ingest.sh -p ./samples/mftecmd/sample_j.csv
    ~~~

    ### stacked mode

    in stacked mode, we simply run the stacked plugin, which in turn use the CSV plugin to parse the data.

    ~~~bash
    TEST_PLUGIN=stacked_example ./test_scripts/test_ingest.sh -p ./samples/mftecmd/sample_j.csv
    ~~~

    see the example in [stacked_example.py](stacked_example.py)

    ### parameters

    CSV plugin support the following custom parameters in the plugin_params.extra dictionary:

    - `delimiter`: set the delimiter for the CSV file (default=",")

    ~~~
    """

    def type(self) -> GulpPluginType:
        return GulpPluginType.INGESTION

    def display_name(self) -> str:
        return "csv"

    @override
    def desc(self) -> str:
        return """stacked plugin on top of csv example"""

    @override
    def version(self) -> str:
        return "1.0"

    @override
    async def _record_to_gulp_document(
        self, record: GulpDocument, record_idx: int
    ) -> GulpDocument:

        # MutyLogger.get_instance().debug("record: %s" % record)
        # tweak event duration ...
        record.event_duration = 9999
        return record

    async def ingest_file(
        self,
        req_id: str,
        ws_id: str,
        user_id: str,
        index: str,
        operation_id: str,
        context_id: str,
        source_id: str,
        file_path: str,
        original_file_path: str = None,
        plugin_params: GulpPluginParameters = None,
        flt: GulpIngestionFilter = None,
    ) -> GulpRequestStatus:
        await super().ingest_file(
            req_id=req_id,
            ws_id=ws_id,
            user_id=user_id,
            index=index,
            operation_id=operation_id,
            context_id=context_id,
            source_id=source_id,
            file_path=file_path,
            original_file_path=original_file_path,
            plugin_params=plugin_params,
            flt=flt,
        )

        # initialize stats
        stats: GulpIngestionStats = await GulpIngestionStats.create_or_get(
            req_id, operation_id=operation_id, context_id=context_id
        )

        # set as stacked
        try:
            lower = await self.setup_stacked_plugin("csv")
            return await lower.ingest_file(
                req_id=req_id,
                ws_id=ws_id,
                user_id=user_id,
                index=index,
                operation_id=operation_id,
                context_id=context_id,
                source_id=source_id,
                file_path=file_path,
                original_file_path=original_file_path,
                plugin_params=plugin_params,
                flt=flt,
            )
        except Exception as ex:
            await self._source_failed(stats, ex)
            return GulpRequestStatus.FAILED
