import pytest

from api.common.custom_exceptions import SchemaNotFoundError
from api.domain.schema import Schema, Column
from api.domain.schema_metadata import Owner, SchemaMetadata, SchemaMetadatas


class TestSchema:
    def setup_method(self):
        self.schema = Schema(
            metadata=SchemaMetadata(
                domain="test_domain",
                dataset="test_dataset",
                sensitivity="test_sensitivity",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=1,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=0,
                    data_type="object",
                    allow_null=False,
                ),
                Column(
                    name="colname3",
                    partition_index=None,
                    data_type="boolean",
                    allow_null=False,
                ),
            ],
        )

    def test_gets_column_names(self):
        expected_column_names = ["colname1", "colname2", "colname3"]

        actual_column_names = self.schema.get_column_names()

        assert actual_column_names == expected_column_names

    def test_gets_column_names_by_data_type(self):
        expected_column_names = ["colname1"]

        actual_column_names = self.schema.get_column_names_by_type("Int64")

        assert actual_column_names == expected_column_names

    def test_gets_numeric_column_dtypes(self):
        expected_columns_dtypes = {"colname1": "Int64", "colname3": "boolean"}

        actual_columns_dtypes = self.schema.get_column_dtypes_to_cast()

        assert actual_columns_dtypes == expected_columns_dtypes

    def test_gets_partitions(self):
        expected_columns = ["colname2", "colname1"]

        actual_columns = self.schema.get_partitions()

        assert actual_columns == expected_columns

    def test_gets_partition_numbers(self):
        expected_partitions_numbers = [0, 1]

        actual_partitions_numbers = self.schema.get_partition_indexes()

        assert actual_partitions_numbers == expected_partitions_numbers

    def test_get_data_types(self):
        expected_data_types = {"Int64", "object", "boolean"}

        actual_data_types = self.schema.get_data_types()

        assert actual_data_types == expected_data_types


class TestSchemaMetadata:
    def test_creates_metadata_from_s3_key(self):
        key = "data/schemas/PUBLIC/hi-there.json"
        result = SchemaMetadata.from_path(key)

        assert result.get_domain() == "hi"
        assert result.get_dataset() == "there"
        assert result.get_sensitivity() == "PUBLIC"

    def test_throws_error_if_sensitivity_is_not_found(self):
        key = "data/schemas/HYPERSECRET/hi-there.json"

        with pytest.raises(ValueError):
            SchemaMetadata.from_path(key)

    def test_schema_path(self):
        schema_metadata = SchemaMetadata(
            domain="DOMAIN",
            dataset="DATASET",
            sensitivity="sensitivity",
            owners=[Owner(name="owner", email="owner@email.com")],
        )
        assert (
            schema_metadata.schema_path()
            == "data/schemas/sensitivity/DOMAIN-DATASET.json"
        )

    def test_schema_name(self):
        schema_metadata = SchemaMetadata(
            domain="DOMAIN",
            dataset="DATASET",
            sensitivity="sensitivity",
            owners=[Owner(name="owner", email="owner@email.com")],
        )
        assert schema_metadata.schema_name() == "DOMAIN-DATASET.json"

    def test_initialises_with_default_tags_when_no_tags_provided(self):
        result = SchemaMetadata(
            domain="domain",
            dataset="dataset",
            sensitivity="PUBLIC",
            owners=[Owner(name="owner", email="owner@email.com")],
        )

        assert result.get_tags() == {"sensitivity": "PUBLIC"}

    def test_gets_tags(self):
        provided_key_value_tags = {
            "tag1_key": "tag1_value",
            "tag2_key": "tag2_value",
            "tag3_key": "tag3_value",
        }
        provided_key_only_tags = ["tag4_key", "tag5_key"]

        result = SchemaMetadata(
            domain="domain",
            dataset="dataset",
            sensitivity="PUBLIC",
            owners=[Owner(name="owner", email="owner@email.com")],
            key_value_tags=provided_key_value_tags,
            key_only_tags=provided_key_only_tags,
        )

        assert result.get_tags() == {
            **provided_key_value_tags,
            **dict.fromkeys(provided_key_only_tags, ""),
            "sensitivity": "PUBLIC",
        }


class TestSchemaMetadatas:
    def test_find_by_domain_and_dataset(self):
        desired_metadata = SchemaMetadata(
            domain="domain2",
            dataset="dataset2",
            sensitivity="sensitivity",
            owners=[Owner(name="owner", email="owner@email.com")],
        )
        data = SchemaMetadatas(
            [
                SchemaMetadata(
                    domain="domain1",
                    dataset="dataset1",
                    sensitivity="sensitivity",
                    owners=[Owner(name="owner", email="owner@email.com")],
                ),
                desired_metadata,
            ]
        )
        result = data.find(domain="domain2", dataset="dataset2")

        assert result is desired_metadata

    def test_raises_error_if_cannot_find_schema_metadata(self):
        data = SchemaMetadatas(
            [
                SchemaMetadata(
                    domain="domain1",
                    dataset="dataset1",
                    sensitivity="sensitivity",
                    owners=[Owner(name="owner", email="owner@email.com")],
                ),
                (
                    SchemaMetadata(
                        domain="domain2",
                        dataset="dataset2",
                        sensitivity="sensitivity",
                        owners=[Owner(name="owner", email="owner@email.com")],
                    )
                ),
            ]
        )

        with pytest.raises(
            SchemaNotFoundError,
            match="Schema not found for domain=domain3 and dataset=dataset3",
        ):
            data.find(domain="domain3", dataset="dataset3")
