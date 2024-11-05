import json
from typing import override

import muty.dict
import muty.file
import muty.jsend
import muty.log
import muty.string
import muty.time
import muty.xml
from evtx import PyEvtxParser
from lxml import etree

from gulp.api.collab.stats import GulpIngestionStats, RequestCanceledError
from gulp.api.collab.structs import GulpRequestStatus
from gulp.api.elastic.structs import GulpDocument, GulpIngestionFilter
from gulp.defs import GulpPluginType
from gulp.plugin import GulpPluginBase
from gulp.plugin_internal import GulpPluginGenericParams
from gulp.utils import logger


class Plugin(GulpPluginBase):
    """
    windows evtx log file processor.
    """

    def type(self) -> GulpPluginType:
        return [GulpPluginType.INGESTION]

    def display_name(self) -> str:
        return "win_evtx"

    @override
    def desc(self) -> str:
        return "Windows EVTX log file processor."

    def _map_evt_code(self, ev_code: str) -> dict:
        """
        better map an event code to fields

        Args:
            ev_code (str): The event code to be converted.
        Returns:
            dict: A dictionary with 'event.category' and 'event.type', or an empty dictionary.
        """
        codes = {
            "100": {"event.category": ["package"], "event.type": ["start"]},
            "106": {"event.category": ["package"], "event.type": ["install"]},
            "140": {"event.category": ["package"], "event.type": ["change"]},
            "141": {"event.category": ["package"], "event.type": ["delete"]},
            "1006": {"event.category": ["host"], "event.type": ["change"]},
            "4624": {  # eventid
                "event.category": ["authentication"],
                "event.type": ["start"],
            },
            "4672": {
                "event.category": ["authentication"],
            },
            "4648": {
                "event.category": ["authentication"],
            },
            "4798": {"event.category": ["iam"]},
            "4799": {"event.category": ["iam"]},
            "5379": {"event.category": ["iam"], "event.type": ["access"]},
            "5857": {"event.category": ["process"], "event.type": ["access"]},
            "5858": {"event.category": ["process"], "event.type": ["error"]},
            "5859": {"event.category": ["process"], "event.type": ["change"]},
            "5860": {"event.category": ["process"], "event.type": ["change"]},
            "5861": {"event.category": ["process"], "event.type": ["change"]},
            "7036": {
                "event.category": ["package"],
                "event.type": ["change"],
            },
            "7040": {
                "event.category": ["package"],
                "event.type": ["change"],
            },
            "7045": {
                "event.category": ["package"],
                "event.type": ["install"],
            },
            "13002": {"event.type": ["change"]},
        }
        if ev_code in codes:
            return codes[ev_code]

        return {}

    @override
    async def _record_to_gulp_document(
        self, record: any, record_idx: int
    ) -> GulpDocument:

        event_original: str = record["data"]
        timestamp = record["timestamp"]
        data_elem = etree.fromstring(event_original.encode("utf-8"))
        e_tree: etree.ElementTree = etree.ElementTree(data_elem)

        d = {}
        for e in e_tree.iter():
            e.tag = muty.xml.strip_namespace(e.tag)
            # logger().debug("found e_tag=%s, value=%s" % (e.tag, e.text))

            # map attrs and values
            if len(e.attrib) == 0:
                # no attribs, i.e. <Opcode>0</Opcode>
                if not e.text or not e.text.strip():
                    # none/empty text
                    # logger().error('skipping e_tag=%s, value=%s' % (e.tag, e.text))
                    continue

                # logger().warning('processing e.attrib=0: e_tag=%s, value=%s' % (e.tag, e.text))
                mapped = self._process_key(e.tag, e.text)
                d.update(mapped)
            else:
                # attribs, i.e. <TimeCreated SystemTime="2019-11-08T23:20:54.670500400Z" />
                for attr_k, attr_v in e.attrib.items():
                    if not attr_v or not attr_v.strip():
                        # logger().error('skipping e_tag=%s, attr_k=%s, attr_v=%s' % (e.tag, attr_k, attr_v))
                        continue
                    if attr_k == "Name":
                        if e.text:
                            text = e.text.strip()
                            k = attr_v
                            v = text
                        else:
                            k = e.tag
                            v = attr_v
                        # logger().warning('processing Name attrib: e_tag=%s, k=%s, v=%s' % (e.tag, k, v))
                    else:
                        k = "%s.%s" % (e.tag, attr_k)
                        v = attr_v
                        # logger().warning('processing attrib: e_tag=%s, k=%s, v=%s' % (e.tag, k, v))
                    mapped = self._process_key(k, v)
                    d.update(mapped)

        # try to map event code to a more meaningful event category and type
        mapped = self._map_evt_code(d.get("event.code"))
        d.update(mapped)

        return GulpDocument(
            self,
            timestamp=timestamp,
            operation=self._operation,
            context=self._context,
            event_original=event_original,
            event_sequence=record_idx,
            log_file_path=self._log_file_path,
            **d,
        )

    async def ingest_file(
        self,
        req_id: str,
        ws_id: str,
        user: str,
        index: str,
        operation: str,
        context: str,
        log_file_path: str,
        plugin_params: GulpPluginGenericParams = None,
        flt: GulpIngestionFilter = None,
    ) -> GulpRequestStatus:
        await super().ingest_file(
            req_id,
            ws_id,
            user,
            index,
            operation,
            context,
            log_file_path,
            plugin_params,
            flt,
        )

        # initialize stats
        stats: GulpIngestionStats = await GulpIngestionStats.create_or_get(
            req_id, user, operation=operation, context=context
        )
        try:
            # initialize plugin
            await self._initialize(mapping_file="windows.json", plugin_params=plugin_params)

            # init parser
            parser = PyEvtxParser(log_file_path)
        except Exception as ex:
            await self._source_failed(stats, ex)
            return GulpRequestStatus.FAILED

        doc_idx = 0
        try:
            for rr in parser.records():
                doc_idx += 1
                try:
                    await self.process_record(stats, rr, doc_idx, flt)
                except RequestCanceledError as ex:
                    break

        except Exception as ex:
            await self._source_failed(stats, ex)
        finally:
            await self._source_done(stats, flt)

        return stats.status
