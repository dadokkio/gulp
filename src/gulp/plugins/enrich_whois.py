import whois
import ipaddress
import json
import socket
import urllib
import datetime
from typing import Any, Optional, override
import muty.file
import muty.json
import muty.log
import muty.os
import muty.string
import muty.time
import muty.xml
from muty.log import MutyLogger
from gulp.api.opensearch.filters import GulpQueryFilter
from gulp.api.opensearch.query import GulpQueryHelpers, GulpQueryParameters
from gulp.plugin import GulpPluginBase, GulpPluginType
from gulp.structs import GulpPluginCustomParameter, GulpPluginParameters
from sqlalchemy.ext.asyncio import AsyncSession

muty.os.check_and_install_package("python-whois", ">=0.9.5")


class Plugin(GulpPluginBase):
    """
    a whois enrichment plugin

    body example:

    {   
        // q is a raw query
        "q": {
            "query": {
            "match_all": {}
            }
        },
        "plugin_params": {
            // those fields will be looked up for whois information
            "host_fields": [ "source.ip", "destination.ip" ]
        }
    }

    example enriched document:

    {
        "@timestamp": "2016-10-06T07:37:27.131044+00:00",
        "gulp.timestamp": 1475739447131043800,
        "gulp.operation_id": "test_operation",
        "gulp.context_id": "66d98ed55d92b6b7382ffc77df70eda37a6efaa1",
        "gulp.source_id": "fabae8858452af6c2acde7f90786b3de3a928289",
        "log.file.path": "/gulp/samples/win_evtx/security_big_sample.evtx",
        "agent.type": "win_evtx",
        "event.original": "{\n  \"Event\": {\n    \"#attributes\": {\n      \"xmlns\": \"http://schemas.microsoft.com/win/2004/08/events/event\"\n    },\n    \"System\": {\n      \"Provider\": {\n        \"#attributes\": {\n          \"Name\": \"Microsoft-Windows-Security-Auditing\",\n          \"Guid\": \"{54849625-5478-4994-a5ba-3e3b0328c30d}\"\n        }\n      },\n      \"EventID\": 5156,\n      \"Version\": 0,\n      \"Level\": 0,\n      \"Task\": 12810,\n      \"Opcode\": 0,\n      \"Keywords\": \"0x8020000000000000\",\n      \"TimeCreated\": {\n        \"#attributes\": {\n          \"SystemTime\": \"2016-10-06T07:37:27.131044Z\"\n        }\n      },\n      \"EventRecordID\": 239152,\n      \"Correlation\": null,\n      \"Execution\": {\n        \"#attributes\": {\n          \"ProcessID\": 4,\n          \"ThreadID\": 80\n        }\n      },\n      \"Channel\": \"Security\",\n      \"Computer\": \"WIN-WFBHIBE5GXZ.example.co.jp\",\n      \"Security\": null\n    },\n    \"EventData\": {\n      \"ProcessID\": 1428,\n      \"Application\": \"\\\\device\\\\harddiskvolume1\\\\windows\\\\system32\\\\dns.exe\",\n      \"Direction\": \"%%14593\",\n      \"SourceAddress\": \"192.168.16.1\",\n      \"SourcePort\": \"49782\",\n      \"DestAddress\": \"202.12.27.33\",\n      \"DestPort\": \"53\",\n      \"Protocol\": 17,\n      \"FilterRTID\": 66305,\n      \"LayerName\": \"%%14611\",\n      \"LayerRTID\": 48\n    }\n  }\n}",
        "event.sequence": 12027,
        "event.code": "5156",
        "gulp.event_code": 5156,
        "event.duration": 1,
        "gulp.unmapped.Guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        "gulp.unmapped.Task": 12810,
        "gulp.unmapped.Keywords": "0x8020000000000000",
        "gulp.unmapped.SystemTime": "2016-10-06T07:37:27.131044Z",
        "winlog.record_id": "239152",
        "process.pid": 1428,
        "process.thread.id": 80,
        "winlog.channel": "Security",
        "winlog.computer_name": "WIN-WFBHIBE5GXZ.example.co.jp",
        "process.executable": "\\device\\harddiskvolume1\\windows\\system32\\dns.exe",
        "network.direction": "%%14593",
        "source.ip": "192.168.16.1",
        "source.port": 49782,
        "destination.ip": "202.12.27.33",
        "destination.port": 53,
        "network.transport": "17",
        "gulp.unmapped.FilterRTID": 66305,
        "gulp.unmapped.LayerName": "%%14611",
        "gulp.unmapped.LayerRTID": 48,
        "_id": "e3b579719b5a49f0f27b3d17fd376ba2",
        "gulp.enrich_whois.destination.ip.network_name": "NSPIXP-2",
        "gulp.enrich_whois.destination.ip.organization_name": "NSPIXP-2",
        "gulp.enrich_whois.destination.ip.as_number": "7500",
        "gulp.enrich_whois.destination.ip.as_organization.name": "M-ROOT-DNS WIDE Project, JP",
        "gulp.enrich_whois.destination.ip.network_cidr": "202.12.27.0/24",
        "gulp.enrich_whois.destination.ip.network_start_addr": "202.12.27.0",
        "gulp.enrich_whois.destination.ip.network_end_addr": "202.12.27.255",
        "gulp.enrich_whois.destination.ip.network_country_code": "JP"
      }
      """

    def __init__(
        self,
        path: str,
        pickled: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(path, pickled=pickled, **kwargs)
        self._whois_cache = {}

    def type(self) -> list[GulpPluginType]:
        return [GulpPluginType.ENRICHMENT]

    def display_name(self) -> str:
        return "enrich_whois"

    @override
    def desc(self) -> str:
        return "whois enrichment plugin"

    @override
    def custom_parameters(self) -> list[GulpPluginCustomParameter]:
        return [
            GulpPluginCustomParameter(
                name="host_fields",
                type="list",
                desc="a list of ip fields to enrich.",
                default_value=["source.ip", "destination.ip", "host.hostname", "dns.question.name"],
            )
        ]

    async def _get_whois(self, host: str) -> Optional[dict]:
        """
        get whois information for an host address.

        this function also caches the results to avoid multiple lookups for the same host.

        Args:
            ip: host address string
        Returns:
            Whois information as a dictionary or None if not found
        """
        if host in self._whois_cache:
            return self._whois_cache[host]

        try:

            #check if field is a url, if so extract the host 
            netloc = urllib.parse.urlparse(host).netloc
            if netloc:
                # netloc was extracted, we successfully parsed a URL
                host = netloc

            # Transform to ECS fields
            whois_info = whois.whois(host)

            # 128.9.0.107
            # remove null fields
            enriched = {}
            for k,v in muty.json.flatten_json(whois_info).items():
                if isinstance(v, datetime.datetime):
                    v: datetime.datetime = v.isoformat()
                
                enriched[k] = v

            # add to cache
            self._whois_cache[host] = enriched
            return enriched

        except (IPDefinedError, socket.error):
            self._whois_cache[host] = None
            return None

    async def _enrich_documents_chunk(self, docs: list[dict], **kwargs) -> list[dict]:
        dd = []
        host_fields = self._custom_params.get("host_fields", [])
        # MutyLogger.get_instance().debug("host_fields: %s, num_docs=%d" % (host_fields, len(docs)))
        for doc in docs:
            # TODO: when opensearch will support runtime mappings, this can be removed and done with "highlight" queries.
            # either, we may also add text mappings to ip fields in the index template..... but keep it as is for now...
            for host_field in host_fields:
                f = doc.get(host_field)
                if not f:
                    continue

                # append flattened whois data to the document                
                whois_data = await self._get_whois(f)
                if whois_data:
                    for key, value in whois_data.items():
                        if value:
                            # also replace . with _ in the field name
                            doc["gulp.%s.%s.%s" %
                                (self.name, host_field.replace(".", "_"), key)] = value
                    dd.append(doc)

        return dd

    @override
    async def enrich_documents(
        self,
        sess: AsyncSession,
        user_id: str,
        req_id: str,
        ws_id: str,
        index: str,
        q: dict = None,
        q_options: GulpQueryParameters = None,
        plugin_params: GulpPluginParameters = None,
    ) -> None:
        # parse custom parameters
        self._parse_custom_parameters(plugin_params)

        host_fields = self._custom_params.get("host_fields", [])
        qq = {
            "query": {
                "bool": {
                    "should": [],
                    "minimum_should_match": 1,
                }
            }
        }

        # select all non-private,non-ipv6 IP addresses
        for host_field in host_fields:
            qq["query"]["bool"]["should"].append(
                {
                    "bool": {
                        "must": [
                            {"exists": {"field": host_field}},
                            {
                                "range": {
                                    host_field: {
                                        "gte": "0.0.0.0",
                                        "lte": "255.255.255.255",
                                    }
                                }
                            },
                        ],
                        "must_not": [
                            {
                                "range": {
                                    host_field: {
                                        "gte": "10.0.0.0",
                                        "lt": "11.0.0.0",
                                    }
                                }
                            },
                            {
                                "range": {
                                    host_field: {
                                        "gte": "172.16.0.0",
                                        "lt": "172.32.0.0",
                                    }
                                }
                            },
                            {
                                "range": {
                                    host_field: {
                                        "gte": "192.168.0.0",
                                        "lt": "192.169.0.0",
                                    }
                                }
                            },
                            {
                                "range": {
                                    host_field: {
                                        "gte": "127.0.0.0",
                                        "lt": "128.0.0.0",
                                    }
                                }
                            },
                        ],
                    }
                }
            )

        if q:
            # merge with provided query
            qq = GulpQueryHelpers.merge_queries(q, qq)

        await super().enrich_documents(
            sess, user_id, req_id, ws_id, index, qq, q_options, plugin_params
        )

    @ override
    async def enrich_single_document(
        self,
        sess: AsyncSession,
        doc_id: str,
        index: str,
        plugin_params: GulpPluginParameters,
    ) -> dict:

        # parse custom parameters
        self._parse_custom_parameters(plugin_params)
        return await super().enrich_single_document(sess, doc_id, index, plugin_params)
