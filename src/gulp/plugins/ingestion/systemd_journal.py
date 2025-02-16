import datetime
import os

import muty.dict
import muty.jsend
import muty.log
import muty.os
import muty.string
import muty.time
import muty.xml

from gulp.api.collab.base import GulpRequestStatus
from gulp.api.collab.stats import TmpIngestStats
from gulp.api.elastic.structs import GulpDocument, GulpIngestionFilter
from gulp.api.mapping.models import FieldMappingEntry, GulpMapping
from gulp.defs import GulpLogLevel, GulpPluginType
from gulp.plugin import PluginBase
from gulp.plugin_internal import GulpPluginParams

# not available on macos, will throw exception
muty.os.check_os(exclude=["windows", "darwin"])
try:
    from systemd import journal
except Exception:
    muty.os.install_package("systemd-python==235")
    from systemd import journal


class Plugin(PluginBase):
    """
    common log format file processor.
    """

    def _normalize_loglevel(self, l: int | str) -> str:
        """
        int to str mapping
        :param l:
        :return:
        """

        ll = int(l)
        if ll == journal.LOG_DEBUG:
            return GulpLogLevel.VERBOSE
        elif ll == journal.LOG_INFO:
            return GulpLogLevel.INFO
        elif ll == journal.LOG_WARNING:
            return GulpLogLevel.WARNING
        elif ll == journal.LOG_ERR:
            return GulpLogLevel.ERROR
        elif ll == journal.LOG_CRIT:
            return GulpLogLevel.CRITICAL
        else:
            # shouldnt happen
            return GulpLogLevel.ALWAYS

    def _to_str_dict(self, rec: dict) -> dict:
        str_dict = {}
        for k, v in rec.items():
            if isinstance(v, datetime.datetime):
                # TODO: keep data as is or to utc?
                str_dict[k] = str(v.astimezone(datetime.timezone.utc))
            # elif type(v) == jounral.Monotonic:
            # m = journal.Monotonic((datetime.timedelta(seconds=2823, microseconds=692301), uuid.uuid1()))
            # str(m) #"journal.Monotonic(timestamp=datetime.timedelta(seconds=2823, microseconds=692301), bootid=UUID('e542849c-4b8b-11ed-aaf9-00216be45548'))"
            # TODO: convert to timestamp?
            else:
                str_dict[k] = str(v)

        return str_dict

    def type(self) -> GulpPluginType:
        return GulpPluginType.INGESTION

    def desc(self) -> str:
        return "Systemd journal log file processor."

    def name(self) -> str:
        return "systemd_journal"

    def version(self) -> str:
        return "1.0"

    async def record_to_gulp_document(
        self,
        operation_id: int,
        client_id: int,
        context: str,
        source: str,
        fs: TmpIngestStats,
        record: any,
        record_idx: int,
        custom_mapping: GulpMapping = None,
        index_type_mapping: dict = None,
        plugin: str = None,
        plugin_params: GulpPluginParams = None,
        extra: dict = None,
        **kwargs,
    ) -> GulpDocument:

        event = self._to_str_dict(record)
        if extra is None:
            extra = {}

        time_str = event["__REALTIME_TIMESTAMP"]
        time_nanosec = muty.time.string_to_epoch_nsec(time_str)
        time_msec = muty.time.nanos_to_millis(time_nanosec)

        raw_text = str(record)
        original_log_level = record["PRIORITY"]
        gulp_log_level = self._normalize_loglevel(original_log_level)  # TODO check

        # map
        # TODO: consider mapping also to syslog.msgid, priority, procid, etc...
        fme: list[FieldMappingEntry] = []
        for k, v in event.items():
            # each event item is a list[str]
            e = self._map_source_key(plugin_params, custom_mapping, k, v, **kwargs)
            for f in e:
                fme.append(f)

        docs = self._build_gulpdocuments(
            fme,
            idx=record_idx,
            timestamp_nsec=time_nanosec,
            timestamp=time_msec,
            operation_id=operation_id,
            context=context,
            plugin=self.name(),
            client_id=client_id,
            raw_event=raw_text,
            original_id=record_idx,
            event_code=str(gulp_log_level.value),
            src_file=os.path.basename(source),
            gulp_log_level=gulp_log_level,
            original_log_level=original_log_level,
        )

        return docs

    async def ingest(
        self,
        index: str,
        req_id: str,
        client_id: int,
        operation_id: int,
        context: str,
        source: str | list[dict],
        ws_id: str,
        plugin_params: GulpPluginParams = None,
        flt: GulpIngestionFilter = None,
        **kwargs,
    ) -> GulpRequestStatus:

        await super().ingest(
            index=index,
            req_id=req_id,
            client_id=client_id,
            operation_id=operation_id,
            context=context,
            source=source,
            ws_id=ws_id,
            plugin_params=plugin_params,
            flt=flt,
            **kwargs,
        )
        fs = TmpIngestStats(source)

        ev_idx = 0

        # initialize mapping
        try:
            index_type_mapping, custom_mapping = await self.ingest_plugin_initialize(
                index,
                source,
                mapping_file="systemd_journal.json",
                plugin_params=plugin_params,
            )

        except Exception as ex:
            fs = self._parser_failed(fs, source, ex)
            return await self._finish_ingestion(
                index, source, req_id, client_id, ws_id, fs=fs, flt=flt
            )

        try:
            with journal.Reader(None, files=[source]) as log_file:
                log_file.log_level(journal.LOG_DEBUG)
                for rr in log_file:
                    try:
                        fs, must_break = await self._process_record(
                            index,
                            rr,
                            ev_idx,
                            self.record_to_gulp_document,
                            ws_id,
                            req_id,
                            operation_id,
                            client_id,
                            context,
                            source,
                            fs,
                            custom_mapping=custom_mapping,
                            index_type_mapping=index_type_mapping,
                            plugin_params=plugin_params,
                            flt=flt,
                            **kwargs,
                        )
                        ev_idx += 1
                        if must_break:
                            break
                    except Exception as ex:
                        fs = self._record_failed(fs, rr, source, ex)

        except Exception as ex:
            fs = self._parser_failed(fs, source, ex)

        # done
        return await self._finish_ingestion(
            index, source, req_id, client_id, ws_id, fs=fs, flt=flt
        )
