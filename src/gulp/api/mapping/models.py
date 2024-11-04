from typing import Optional

from pydantic import BaseModel, Field

"""
mapping files structure:
{
    mapping_id_1: {
        GulpMapping: {
            "fields": {
                field_1: {
                    GulpMappingField
                },
                field_2: {
                    GulpMappingField
                },
                ...        
            }
        }
    },
    mapping_id_2: {
        GulpMapping: {
            "fields": {
                field_1: {
                    GulpMappingField
                },
                field_2: {
                    GulpMappingField
                },
                ...        
            }
        }
    },
    ...
}
"""

class GulpMappingField(BaseModel):
    """
    defines how to map a single field, including field-specific options.
    """

    class Config:
        extra = "allow"

    ecs: Optional[list[str]] = Field(None,
        description="one or more ECS field names to map the source field to in the resulting document.",
        min_length=1,
    )
    opt_extra_doc_with_event_code: Optional[str] = Field(
        None,
        description='if this is set, the creation of an extra document is triggered with the given "event.code" and "@timestamp" set to this field value.',
    )
    opt_is_timestamp_chrome: Optional[bool] = Field(
        False,
        description="if set, the corresponding value is a webkit timestamp (from 1601) and will be converted to nanoseconds from unix epoch.",
    )


class GulpMapping(BaseModel):
    """
    defines a logsource -> gulp document mapping
    """

    class Config:
        extra = "allow"

    fields: dict[str, GulpMappingField] = Field(...,
        description="field mappings { raw_field: { GulpMappingField } } to translate a logsource to gulp document.",
        min_length=1,
    )
    agent_type: Optional[str] = Field(None,
        description='if set, documents generated by this mapping have "agent.type" set to this value. either, the plugin is responsible for setting this.',
    )

    event_code: Optional[str] = Field(None,
        description='if set, documents generated by this mapping have "event.code" set to this value (and "gulp.event.code" to the corresponding numeric value). either, the plugin is responsible for setting this.',
    )
    description: Optional[str] = Field(
        None,
        description="if set, mapping's description.",
    )
 
class GulpMappingFileMetadata(BaseModel):
    """
    metadata for a mapping file.
    """
    class Config:
        extra = "allow"
    
    plugin: list[str] = Field(...,
        description="one or more plugin names that this mapping file is associated with.",
    )
class GulpMappingFile(BaseModel):
    """
    a mapping file, containing one or more GulpMapping objects.
    """

    class Config:
        extra = "allow"

    mappings: dict[str, GulpMapping] = Field(...,
        description="defined mappings for this mapping file, key is the `mapping_id`", min_length=1,
    )
    metadata: Optional[GulpMappingFileMetadata] = Field(None,
        description="metadata for the mapping file.",
    )
    
