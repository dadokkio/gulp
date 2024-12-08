import json
from typing import Optional, TypeVar, Union, override

import muty.crypto
import muty.dict
import muty.string
import muty.time
from muty.log import MutyLogger
from pydantic import BaseModel, ConfigDict, Field, model_validator
from muty.pydantic import autogenerate_model_example, autogenerate_model_example_by_class
from gulp.api.mapping.models import GulpMapping
from gulp.api.opensearch.filters import QUERY_DEFAULT_FIELDS, GulpBaseDocumentFilter
from gulp.api.rest.test_values import (
    TEST_CONTEXT_ID,
    TEST_OPERATION_ID,
    TEST_SOURCE_ID,
)

T = TypeVar("T", bound="GulpBaseDocumentFilter")


class GulpBasicDocument(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        # solves the issue of not being able to populate fields using field name instead of alias
        populate_by_name=True,
    )

    id: str = Field(
        description='"_id": the unique identifier of the document.',
        alias="_id",
        example="1234567890abcdef1234567890abcdef",
    )
    timestamp: str = Field(
        description='"@timestamp": document timestamp, in iso8601 format.',
        alias="@timestamp",
        example="2021-01-01T00:00:00Z",
    )
    gulp_timestamp: int = Field(
        description='"@timestamp": document timestamp in nanoseconds from unix epoch',
        alias="gulp.timestamp",
        example=1609459200000000000,
    )
    invalid_timestamp: bool = Field(
        False,
        description='True if "@timestamp" is invalid and set to 1/1/1970 (the document should be checked, probably ...).',
        alias="gulp.timestamp_invalid",
        example=False,
    )
    operation_id: str = Field(
        description='"gulp.operation_id": the operation ID the document is associated with.',
        alias="gulp.operation_id",
        example=TEST_OPERATION_ID,
    )
    context_id: str = Field(
        description='"gulp.context_id": the context (i.e. an host name) the document is associated with.',
        alias="gulp.context_id",
        example=TEST_CONTEXT_ID,
    )
    source_id: str = Field(
        description='"gulp.source_id": the source the document is associated with.',
        alias="gulp.source_id",
        example=TEST_SOURCE_ID,
    )


class GulpDocument(GulpBasicDocument):
    """
    represents a Gulp document.
    """

    log_file_path: Optional[str] = Field(
        None,
        description='"log.file.path": the original log file name or path.',
        alias="log.file.path",
        example="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    )
    agent_type: str = Field(
        None,
        description='"agent.type": the ingestion source, i.e. gulp plugin.name().',
        alias="agent.type",
        example="win_evtx",
    )
    event_original: str = Field(
        None,
        description='"event.original": the original event as text.',
        alias="event.original",
        example="raw event content",
    )
    event_sequence: int = Field(
        0,
        description='"event.sequence": the sequence number of the document in the source.',
        alias="event.sequence",
        example=1,
    )
    event_code: Optional[str] = Field(
        "0",
        description='"event.code": the event code, "0" if missing.',
        alias="event.code",
        example="1234",
    )
    gulp_event_code: Optional[int] = Field(
        0,
        description='"gulp.event_code": "event.code" as integer.',
        alias="gulp.event_code",
        example=1234,
    )
    event_duration: Optional[int] = Field(
        1,
        description='"event.duration": the duration of the event in nanoseconds, defaults to 1.',
        alias="event.duration",
        example=1,
    )

    @classmethod
    def example(cls) -> dict:
        """
        builds example of the model

        Returns:
            dict: the model example
        """
        return autogenerate_model_example_by_class(cls)

    @override
    @classmethod
    def model_json_schema(cls, *args, **kwargs):
        return autogenerate_model_example(cls, *args, **kwargs)

    @staticmethod
    def ensure_timestamp(
        timestamp: str,
        dayfirst: bool = None,
        yearfirst: bool = None,
        fuzzy: bool = None,
    ) -> tuple[str, int, bool]:
        """
        Ensure the timestamp is in iso8601 format.

        Args:
            timestamp (str): The timestamp.
            dayfirst (bool, optional): If set, parse the timestamp with dayfirst=True. Defaults to None (use dateutil.parser default).
            yearfirst (bool, optional): If set, parse the timestamp with yearfirst=True. Defaults to None (use dateutil.parser default).
            fuzzy (bool, optional): If set, parse the timestamp with fuzzy=True. Defaults to None (use dateutil.parser default).
        Returns:
            tuple[str, int, bool]: The timestamp in iso8601 format, the timestamp in nanoseconds from unix epoch, and a boolean indicating if the timestamp is invalid.
        """
        epoch_start: str = "1970-01-01T00:00:00Z"
        if not timestamp:
            return epoch_start, 0, True

        try:
            ts = muty.time.ensure_iso8601(timestamp, dayfirst, yearfirst, fuzzy)
            if timestamp.isdigit():
                # timestamp is in seconds/milliseconds/nanoseconds from unix epoch
                ns = muty.time.number_to_nanos(timestamp)
            else:
                ns = muty.time.string_to_epoch_nsec(
                    ts, dayfirst=dayfirst, yearfirst=yearfirst, fuzzy=fuzzy
                )
            return ts, ns, False
        except Exception as e:
            # invalid timestamp
            # MutyLogger.get_instance().error(f"invalid timestamp: {timestamp}, {e}")
            return epoch_start, 0, True

    @override
    def __init__(
        self,
        plugin_instance,
        operation_id: str | int,
        context_id: str,
        source_id: str,
        event_original: str,
        event_sequence: int,
        timestamp: str = None,
        event_code: str = "0",
        event_duration: int = 1,
        log_file_path: str = None,
        **kwargs,
    ) -> None:
        """
        Initialize a GulpDocument instance.

        Args:
            plugin_instance: The calling PluginBase
            operation_id (str): The operation id on gulp collab database.
            context_id (str): The context id on gulp collab database.
            source_id (str): The source id on gulp collab database.
            event_original (str): The original event data.
            event_sequence (int): The sequence number of the event.
            timestamp (str, optional): The timestamp of the event as a number or numeric string (seconds/milliseconds/nanoseconds from unix epoch)<br>
                or a string in a format supported by dateutil.parser.<br>
                if None, assumes **kwargs has been already processed by the mapping engine and contains {"@timestamp", "gulp.timestamp" and possibly "gulp.timestamp_invalid" flag}
            event_code (str, optional): The event code. Defaults to "0".
            event_duration (int, optional): The duration of the event. Defaults to 1.
            log_file_path (str, optional): The source log file path. Defaults to None.

            **kwargs: Additional keyword arguments to be added as attributes.
                - ignore_default_event_code (bool, optional): If True, do not use the default event code from the mapping. Defaults to False.

            Returns:
            None
        """
        # replace alias keys in kwargs with their corresponding field names
        # (i.e. "event.code" -> "event_code")
        # this is needed to i.e. augment already existing documents

        kwargs = GulpDocumentFieldAliasHelper.set_kwargs_and_fix_aliases(kwargs)
        mapping: GulpMapping = plugin_instance.selected_mapping()
        ignore_default_event_code = kwargs.pop("__ignore_default_event_code__", False)

        # Build initial data dict
        data = {
            "operation_id": operation_id,
            "context_id": context_id,
            # force agent type from mapping or default to plugin name
            "agent_type": (
                mapping.agent_type
                if mapping and mapping.agent_type
                else plugin_instance.bare_filename
            ),
            "event_original": event_original,
            "event_sequence": event_sequence,
            # force event code from mapping or default to event_code
            "event_code": (
                mapping.event_code
                if mapping and mapping.event_code and not ignore_default_event_code
                else event_code
            ),
            "event_duration": event_duration,
            "source_id": source_id,
            "log_file_path": log_file_path,
            # add each kwargs as an attribute as-is (may contain event.code, @timestamp, and other fields previously set above, they will be overwritten)
            # @timestamp may have been mapped and already checked for validity in plugin._process_key()
            # if so, we will find it here...
        }
        data.update(kwargs)

        # handle timestamp
        if "timestamp" not in data:
            # use timestamp from argument
            data["timestamp"] = timestamp

        # ensure timestamp is valid
        ts, ts_nanos, invalid = GulpDocument.ensure_timestamp(
            data["timestamp"],
            dayfirst=mapping.timestamp_dayfirst if mapping else None,
            yearfirst=mapping.timestamp_yearfirst if mapping else None,
            fuzzy=mapping.timestamp_fuzzy if mapping else None,
        )
        data["timestamp"] = ts
        data["gulp_timestamp"] = ts_nanos
        data["invalid_timestamp"] = invalid

        # add gulp_event_code (event code as a number)
        data["gulp_event_code"] = (
            int(data["event_code"])
            if data["event_code"].isnumeric()
            else muty.crypto.hash_xxh64_int(data["event_code"])
        )

        # id is a hash of the document
        data["id"] = muty.crypto.hash_xxh128(
            f"{data['event_original']}{data['event_code']}{data['event_sequence']}"
        )

        # initialize with complete data (and validate)
        super().__init__(**data)

    def __repr__(self) -> str:
        return f"GulpDocument(timestamp={self.timestamp}, gulp_timestamp={self.gulp_timestamp}, operation_id={self.operation_id}, context_id={self.context_id}, agent_type={self.agent_type}, event_sequence={self.event_sequence}, event_code={self.event_code}, event_duration={self.event_duration}, source_id={self.source_id}"

    @override
    def model_dump(
        self,
        lite: bool = False,
        exclude_none: bool = True,
        exclude_unset: bool = True,
        **kwargs,
    ) -> dict:
        """
        Convert the model instance to a dictionary.
        Args:
            lite (bool): If True, return a subset of the dictionary with "_id", "@timestamp",
                  "gulp.context_id", "gulp.operation_id", and "gulp.source_id" keys.
                         Defaults to False.
            **kwargs: Additional keyword arguments to pass to the parent class model_dump method.
        Returns:
            dict: A dictionary representation of the model instance
        """
        d = super().model_dump(
            exclude_none=exclude_none, exclude_unset=exclude_unset, **kwargs
        )
        if lite:
            # return just a minimal subset
            for k in list(d.keys()):
                if k not in QUERY_DEFAULT_FIELDS:
                    d.pop(k, None)
        return d


class GulpDocumentFieldAliasHelper:
    """
    internal helper class to fix alias keys in kwargs with their corresponding field names.
    """

    _alias_to_field_cache: dict[str, str] = {}

    @staticmethod
    def set_kwargs_and_fix_aliases(kwargs: dict) -> dict:
        """
        Replace alias keys in kwargs with their corresponding field names.

        Args:
            kwargs (dict): The keyword arguments to fix.
        Returns:
            dict: The fixed keyword arguments.
        """
        if not GulpDocumentFieldAliasHelper._alias_to_field_cache:
            # initialize on first call
            GulpDocumentFieldAliasHelper._alias_to_field_cache = {
                field.alias: name
                for name, field in GulpDocument.model_fields.items()
                if field.alias
            }
        return {
            GulpDocumentFieldAliasHelper._alias_to_field_cache.get(k, k): v
            for k, v in kwargs.items()
        }


class GulpRawDocumentMetadata(BaseModel):
    """
    metadata for a GulpRawDocument
    """

    model_config = ConfigDict(
        # solves the issue of not being able to populate fields using field name instead of alias
        populate_by_name=True,
        extra="allow",
    )
    timestamp: str = Field(
        ...,
        description="the document timestamp, in iso8601 format.",
        example="2021-01-01T00:00:00Z",
        alias="@timestamp",
    )
    event_original: str = Field(
        ...,
        description="the original event as text.",
        example="raw event content",
        alias="event.original",
    )
    event_code: Optional[str] = Field(
        "0",
        description="the event code, defaults to '0'.",
        example="1234",
        alias="event.code",
    )


class GulpRawDocument(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        # solves the issue of not being able to populate fields using field name instead of alias
        populate_by_name=True,
    )

    metadata: GulpRawDocumentMetadata = Field(
        ...,
        description="the document metadata.",
        alias="__metadata__",
    )
    doc: dict = Field(
        ...,
        description="the document as key/value pairs, to generate the `GulpDocument` with.",
    )

    @override
    @classmethod
    def model_json_schema(cls, *args, **kwargs):
        return autogenerate_model_example(cls, *args, **kwargs)
