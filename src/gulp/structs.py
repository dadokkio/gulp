"""Gulp global definitions."""

from enum import StrEnum
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

from gulp.api.mapping.models import GulpMapping
from muty.pydantic import (
    autogenerate_model_example_by_class,
)


class ObjectAlreadyExists(Exception):
    pass


class ObjectNotFound(Exception):
    pass


class GulpAPIParameter(BaseModel):
    """
    describes a parameter for a Gulp API method.
    """
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "ignore_mapping",
                    "type": "bool",
                    "default_value": False,
                    "desc": "ignore mapping file and leave the field as is.",
                    "required": True,
                }
            ]
        }
    )

    name: str = Field(..., description="the parameter.")
    type: Literal["bool", "str", "int", "float", "dict", "list"] = Field(
        ..., description="parameter type."
    )
    default_value: Optional[Any] = Field(None, description="default value.")
    desc: Optional[str] = Field(None, description="parameter description.")
    location: Optional[Literal["query", "header", "body"]] = Field(
        default="query", description="where the parameter is located, for API requests.")
    required: Optional[bool] = Field(
        False, description="is the parameter required ?")


class GulpAPIMethod(BaseModel):
    """
    describes a Gulp API method.
    """
    method: Literal["PUT", "GET", "POST", "DELETE", "PATCH"] = Field(
        ..., description="the method to be used"),
    url: str = Field(...,
                     description="the endpoint url, relative to the base host"),
    params: Optional[list[GulpAPIParameter]] = Field(
        [], description="list of parameters for the method")


class GulpPluginParameters(BaseModel):
    """
    common parameters for a plugin, to be passed to ingest and query API.

    this may also include GulpPluginCustomParameter.name entries specific to the plugin
    """

    model_config = ConfigDict(
        extra="allow",
        json_schema_extra={
            "examples": [
                {
                    "mapping_file": "mftecmd_csv.json",
                    "mappings": autogenerate_model_example_by_class(GulpMapping),
                    "mapping_id": "record",
                    "additional_mapping_files": [
                        ("mftecmd_csv.json", "record"),
                        ("mftecmd_csv.json", "file"),
                    ],
                    "custom_parameters": {
                        "custom1": "parameter1",
                        "custom2": "parameter2",
                    }
                }
            ]
        },
    )
    mapping_file: Optional[str] = Field(
        None,
        description="used for ingestion only: mapping file name in `gulp/mapping_files` directory to read `GulpMapping` entries from. (if `mappings` is set, this is ignored).",
    )
    additional_mapping_files: Optional[list[tuple[str, str]]] = Field(
        None,
        description="""
if this is set, allows to specify further mapping files and mapping IDs with a tuple of (mapping_file, mapping_id) to load and merge additional mappings from another file.

- each mapping loaded from `additional_mapping_files` will be merged with the main `mapping file.mapping_id` fields.
- ignored if `mappings` is set.
""",
    )
    mappings: Optional[dict[str, GulpMapping]] = Field(
        None,
        description="""
used for ingestion only: a dictionary of one or more { mapping_id: GulpMapping } to use directly.
- `mapping_file` and `additional_mapping_files` are ignored if this is set.
""",
    )

    mapping_id: Optional[str] = Field(
        None,
        description="used for ingestion only: the `GulpMapping` to select in `mapping_file` or `mappings` object: if not set, the first found GulpMapping is used.",
    )

    override_chunk_size: Optional[int] = Field(
        None,
        description="this is used to override the websocket chunk size for the request, which is normally taken from configuration 'documents_chunk_size'.",
    )

    custom_parameters: Optional[dict] = Field(
        {},
        description="optional additional plugin parameters defined in `Plugin.custom_parameters()`.",
    )

    def is_empty(self) -> bool:
        """
        a mapping is empty if mappings or mapping_file or mapping_id is empty

        Returns:
            bool: True if all parameters are None, False otherwise
        """
        if (
            self.mappings is not None
            or self.mapping_file is not None
            or self.override_chunk_size is not None
            or len(self.custom_parameters) > 0
            or len(self.model_extra) > 0
        ):
            return False
        return True


class GulpPluginCustomParameter(GulpAPIParameter):
    """
    this is used by the UI through the plugin.options() method to list the supported options, and their types, for a plugin.

    `name` may also be a key in the `GulpPluginParameters.custom_parameters` object, to list additional parameters specific for the plugin.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "ignore_mapping",
                    "type": "bool",
                    "default_value": False,
                    "desc": "ignore mapping file and leave the field as is.",
                    "required": True,
                }
            ]
        }
    )


class GulpNameDescriptionEntry(BaseModel):
    """
    indicates the sigma support for a plugin, to be returned by the plugin.sigma_support() method.

    refer to [sigma-cli](
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "opensearch",
                    "description": "the one to use to query Gulp.",
                }
            ]
        }
    )
    name: str = Field(
        ...,
        description="name for the entry.",
    )
    description: Optional[str] = Field(
        None,
        description="a description",
    )


class GulpSortOrder(StrEnum):
    """
    specifies the sort types for API accepting the "sort" parameter
    """

    ASC = "asc"
    DESC = "desc"
