from typing import List, Dict, Optional, Set

from pydantic.main import BaseModel

from api.domain.data_types import DataTypes
from api.domain.schema_metadata import Owner, SchemaMetadata


class Column(BaseModel):
    name: str
    partition_index: Optional[int]
    data_type: str
    allow_null: bool
    format: Optional[str] = None


class Schema(BaseModel):
    metadata: SchemaMetadata
    columns: List[Column]

    def get_domain(self) -> str:
        return self.metadata.get_domain()

    def get_dataset(self) -> str:
        return self.metadata.get_dataset()

    def get_sensitivity(self) -> str:
        return self.metadata.get_sensitivity()

    def get_custom_tags(self) -> Dict[str, str]:
        return self.metadata.get_custom_tags()

    def get_tags(self) -> Dict[str, str]:
        return self.metadata.get_tags()

    def get_owners(self) -> Optional[List[Owner]]:
        return self.metadata.get_owners()

    def get_update_behaviour(self) -> str:
        return self.metadata.get_update_behaviour()

    def get_column_names(self) -> List[str]:
        return [column.name for column in self.columns]

    def get_column_dtypes_to_cast(self) -> Dict[str, str]:
        return {
            column.name: column.data_type
            for column in self.columns
            if column.data_type in DataTypes.data_types_to_cast()
        }

    def get_partitions(self) -> List[str]:
        sorted_cols = self.get_partition_columns()
        return [column.name for column in sorted_cols]

    def get_partition_indexes(self) -> List[int]:
        sorted_cols = self.get_partition_columns()
        return [column.partition_index for column in sorted_cols]

    def get_data_types(self) -> Set[str]:
        return {column.data_type for column in self.columns}

    def get_columns_by_type(self, d_type: str) -> List[Column]:
        return [column for column in self.columns if column.data_type == d_type]

    def get_column_names_by_type(self, d_type: str) -> List[str]:
        return [column.name for column in self.columns if column.data_type == d_type]

    def get_partition_columns(self) -> List[Column]:
        return sorted(
            [column for column in self.columns if column.partition_index is not None],
            key=lambda x: x.partition_index,
        )
