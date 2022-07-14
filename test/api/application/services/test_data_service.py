from unittest.mock import Mock, patch

import pandas as pd
from api.common.config.aws import RESOURCE_PREFIX
import pytest

from api.application.services.data_service import DataService
from api.common.custom_exceptions import (
    ProtectedDomainDoesNotExistError,
    SchemaNotFoundError,
    CrawlerIsNotReadyError,
    GetCrawlerError,
    CrawlerStartFailsError,
    SchemaError,
    ConflictError,
    UserError,
)
from api.domain.enriched_schema import (
    EnrichedSchema,
    EnrichedSchemaMetadata,
    EnrichedColumn,
)
from api.domain.schema import Schema, SchemaMetadata, Owner, Column, UpdateBehaviour
from api.domain.sql_query import SQLQuery
from test.test_utils import set_encoded_content


class TestUploadSchema:
    def setup_method(self):
        self.s3_adapter = Mock()
        self.crawler_adapter = Mock()
        self.query_adapter = Mock()
        self.protected_domain_service = Mock()
        self.data_service = DataService(
            self.s3_adapter,
            self.crawler_adapter,
            self.query_adapter,
            self.protected_domain_service,
        )
        self.valid_schema = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )

    def test_upload_schema(self):
        self.s3_adapter.find_schema.return_value = None
        self.s3_adapter.save_schema.return_value = "some-other.json"

        result = self.data_service.upload_schema(self.valid_schema)

        self.s3_adapter.save_schema.assert_called_once_with(
            "some", "other", "PUBLIC", self.valid_schema
        )
        assert result == "some-other.json"

    def test_check_for_protected_domain_success(self):
        schema = Schema(
            metadata=SchemaMetadata(
                domain="domain",
                dataset="dataset",
                sensitivity="PROTECTED",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
            ],
        )
        self.protected_domain_service.list_domains = Mock(
            return_value=["domain", "other"]
        )

        result = self.data_service.check_for_protected_domain(schema)

        self.protected_domain_service.list_domains.assert_called_once()
        assert result == "domain"

    def test_check_for_protected_domain_fails(self):
        schema = Schema(
            metadata=SchemaMetadata(
                domain="domain",
                dataset="dataset",
                sensitivity="PROTECTED",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
            ],
        )
        self.protected_domain_service.list_domains = Mock(return_value=["other"])

        with pytest.raises(ProtectedDomainDoesNotExistError):
            self.data_service.check_for_protected_domain(schema)

    def test_upload_schema_throws_error_when_schema_already_exists(self):
        self.s3_adapter.find_schema.return_value = self.valid_schema

        with pytest.raises(ConflictError, match="Schema already exists"):
            self.data_service.upload_schema(self.valid_schema)

    def test_upload_schema_throws_error_when_schema_invalid(self):
        self.s3_adapter.find_schema.return_value = None

        invalid_partition_index = -1
        invalid_schema = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=invalid_partition_index,
                    data_type="Int64",
                    allow_null=True,
                )
            ],
        )

        with pytest.raises(SchemaError):
            self.data_service.upload_schema(invalid_schema)


class TestUploadDataset:
    def setup_method(self):
        self.s3_adapter = Mock()
        self.glue_adapter = Mock()
        self.query_adapter = Mock()
        self.protected_domain_service = Mock()
        self.data_service = DataService(
            self.s3_adapter,
            self.glue_adapter,
            self.query_adapter,
            self.protected_domain_service,
        )
        self.valid_schema = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )

    # Happy Path -------------------------------------
    @patch("api.application.services.data_service.generate_partitioned_data")
    def test_upload_dataset_in_one_not_partitioned_file(self, mock_partitioner):
        file_contents = set_encoded_content(
            "colname1,colname2\n" "1234,Carlos\n" "4567,Ada\n"
        )
        expected = pd.DataFrame(
            {
                "colname1": [1234, 4567],
                "colname2": ["Carlos", "Ada"],
            }
        )
        expected["colname1"] = expected["colname1"].astype(dtype=pd.Int64Dtype())

        self.s3_adapter.find_schema.return_value = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=None,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )
        partitioned_data = [("", expected)]
        mock_partitioner.return_value = partitioned_data

        self.data_service.generate_raw_filename = Mock(
            return_value=("2022-03-03T12:00:00-data.csv")
        )

        filename = self.data_service.upload_dataset(
            RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
        )
        assert filename == "2022-03-03T12:00:00-data.csv"

        self.s3_adapter.upload_partitioned_data.assert_called_once_with(
            "some", "other", "2022-03-03T12:00:00-data.csv", partitioned_data
        )

        self.glue_adapter.update_catalog_table_config.assert_called_once_with(
            "some", "other"
        )

        self.data_service.generate_raw_filename.assert_called_once_with("data.csv")

    @patch("api.application.services.data_service.generate_partitioned_data")
    def test_upload_dataset_in_two_partitioned_files(self, mock_partitioner):
        file_contents = set_encoded_content(
            "colname1,colname2\n" "1234,Carlos\n" "4567,Ada\n"
        )
        expected = pd.DataFrame(
            {
                "colname1": [1234, 4567],
                "colname2": ["Carlos", "Ada"],
            }
        )
        expected["colname1"] = expected["colname1"].astype(dtype=pd.Int64Dtype())

        self.s3_adapter.find_schema.return_value = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )
        partitioned_data = [
            ("colname1=1234", pd.DataFrame({"colname2": ["Carlos"]})),
            ("colname1=4567", pd.DataFrame({"colname2": ["Ada"]})),
        ]
        mock_partitioner.return_value = partitioned_data

        self.data_service.generate_raw_filename = Mock(
            return_value=("2022-03-02T12:00:00-data.csv")
        )

        filename = self.data_service.upload_dataset(
            RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
        )
        assert filename == "2022-03-02T12:00:00-data.csv"

        self.s3_adapter.upload_partitioned_data.assert_called_once_with(
            "some", "other", "2022-03-02T12:00:00-data.csv", partitioned_data
        )

        self.glue_adapter.update_catalog_table_config.assert_called_once_with(
            "some", "other"
        )

    # Happy Path -------------------------------------
    @patch("api.application.services.data_service.generate_partitioned_data")
    def test_upload_dataset_with_overwrite_behaviour_with_no_partition(
        self, mock_partitioner
    ):
        file_contents = set_encoded_content(
            "colname1,colname2\n" "1234,Carlos\n" "4567,Ada\n"
        )
        expected = pd.DataFrame(
            {
                "colname1": [1234, 4567],
                "colname2": ["Carlos", "Ada"],
            }
        )
        expected["colname1"] = expected["colname1"].astype(dtype=pd.Int64Dtype())

        self.s3_adapter.find_schema.return_value = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
                update_behaviour=UpdateBehaviour.OVERWRITE.value,
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=None,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )
        partitioned_data = [("", expected)]
        mock_partitioner.return_value = partitioned_data

        filename = self.data_service.upload_dataset(
            RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
        )
        assert filename == "some.csv"

        self.s3_adapter.upload_partitioned_data.assert_called_once_with(
            "some", "other", "some.csv", partitioned_data
        )

        self.glue_adapter.update_catalog_table_config.assert_called_once_with(
            "some", "other"
        )

    @patch("api.application.services.data_service.generate_partitioned_data")
    def test_upload_dataset_with_overwrite_behaviour_with_two_partitions(
        self, mock_partitioner
    ):
        file_contents = set_encoded_content(
            "colname1,colname2\n" "1234,Carlos\n" "4567,Ada\n"
        )
        expected = pd.DataFrame(
            {
                "colname1": [1234, 4567],
                "colname2": ["Carlos", "Ada"],
            }
        )
        expected["colname1"] = expected["colname1"].astype(dtype=pd.Int64Dtype())

        self.s3_adapter.find_schema.return_value = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
                update_behaviour=UpdateBehaviour.OVERWRITE.value,
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )
        partitioned_data = [
            ("colname1=1234", pd.DataFrame({"colname2": ["Carlos"]})),
            ("colname1=4567", pd.DataFrame({"colname2": ["Ada"]})),
        ]
        mock_partitioner.return_value = partitioned_data

        filename = self.data_service.upload_dataset(
            RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
        )
        assert filename == "some.csv"

        self.s3_adapter.upload_partitioned_data.assert_called_once_with(
            "some", "other", "some.csv", partitioned_data
        )

        self.glue_adapter.update_catalog_table_config.assert_called_once_with(
            "some", "other"
        )

    # E2E flow ---------------------------------------
    @patch("api.application.services.data_service.generate_partitioned_data")
    def test_upload_formatted_dataset_after_transformation_and_validation(
        self, mock_partitioner
    ):
        file_contents = set_encoded_content(
            "DaTe,Va!lu-e\n"  # Incorrectly formatted column headings
            "12/06/2012,Carolina\n"  # Date format to be transformed
            "12/07/2012,Albertine\n"
            ",\n"  # Entirely null row
        )

        self.s3_adapter.find_schema.return_value = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="date",
                    partition_index=None,
                    data_type="date",
                    format="%d/%m/%Y",
                    allow_null=True,
                ),
                Column(
                    name="value",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )

        expected_transformed_df = pd.DataFrame(
            {
                "date": ["2012-06-12", "2012-07-12"],
                "value": ["Carolina", "Albertine"],
            }
        )

        mock_partitioner.return_value(expected_transformed_df)

        self.data_service.generate_raw_filename = Mock(
            return_value=("2022-03-03T12:00:00-data.csv")
        )

        filename = self.data_service.upload_dataset(
            RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
        )
        assert filename == "2022-03-03T12:00:00-data.csv"

        #  Checking mock calls with dataframes does not work because we need to call the df.equals() method
        partitioner_args = mock_partitioner.call_args.args
        upload_args = self.s3_adapter.upload_partitioned_data.call_args.args

        assert partitioner_args[1].equals(expected_transformed_df)

        assert upload_args[0] == "some"
        assert upload_args[1] == "other"
        assert upload_args[2] == "2022-03-03T12:00:00-data.csv"
        assert upload_args[3].equals(expected_transformed_df)

        self.glue_adapter.update_catalog_table_config.assert_called_once_with(
            "some", "other"
        )

    # Schema retrieval -------------------------------
    def test_raises_error_when_schema_does_not_exist(self):
        file_contents = set_encoded_content(
            "colname1,colname2\n" "1234,Carlos\n" "4567,Ada\n"
        )

        self.s3_adapter.find_schema.return_value = None

        with pytest.raises(SchemaNotFoundError):
            self.data_service.upload_dataset(
                RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
            )

        self.s3_adapter.find_schema.assert_called_once_with("some", "other")

    # Crawler state and trigger ----------------------
    def test_upload_dataset_fails_when_unable_to_get_crawler_state(self):
        file_contents = set_encoded_content(
            "colname1,colname2\n" "1234,Carlos\n" "4567,Ada\n"
        )

        self.s3_adapter.find_schema.return_value = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=None,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )

        self.glue_adapter.check_crawler_is_ready.side_effect = GetCrawlerError("msg")

        with pytest.raises(GetCrawlerError):
            self.data_service.upload_dataset(
                RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
            )

        self.glue_adapter.check_crawler_is_ready.assert_called_once_with(
            RESOURCE_PREFIX, "some", "other"
        )

    def test_upload_dataset_fails_when_crawler_is_not_ready(self):
        file_contents = set_encoded_content(
            "colname1,colname2\n" "1234,Carlos\n" "4567,Ada\n"
        )

        self.s3_adapter.find_schema.return_value = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=None,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )

        self.glue_adapter.check_crawler_is_ready.side_effect = CrawlerIsNotReadyError(
            "msg"
        )

        with pytest.raises(CrawlerIsNotReadyError):
            self.data_service.upload_dataset(
                RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
            )

        self.glue_adapter.check_crawler_is_ready.assert_called_once_with(
            RESOURCE_PREFIX, "some", "other"
        )

    def test_upload_dataset_starts_crawler(self):
        file_contents = set_encoded_content(
            "colname1,colname2\n" "1234,Carlos\n" "4567,Ada\n"
        )

        self.s3_adapter.find_schema.return_value = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=None,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )

        self.data_service.upload_dataset(
            RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
        )

        self.glue_adapter.start_crawler.assert_called_once_with(
            RESOURCE_PREFIX, "some", "other"
        )

    def test_upload_dataset_fails_to_start_crawler(self):
        file_contents = set_encoded_content(
            "colname1,colname2\n" "1234,Carlos\n" "4567,Ada\n"
        )

        self.s3_adapter.find_schema.return_value = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=None,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )

        self.glue_adapter.start_crawler.side_effect = CrawlerStartFailsError(
            "Some thing"
        )

        with pytest.raises(CrawlerStartFailsError):
            self.data_service.upload_dataset(
                RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
            )

    # Persist raw copy of data -------------------------------
    def test_upload_dataset_persists_raw_copy_of_data(self):
        file_contents = set_encoded_content(
            "colname1,colname2\n" "1234,Carlos\n" "4567,Ada\n"
        )

        self.s3_adapter.find_schema.return_value = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
            ],
        )
        self.data_service.generate_raw_filename = Mock(
            return_value=("2022-03-03T12:00:00-data.csv")
        )

        self.data_service.upload_dataset(
            RESOURCE_PREFIX, "some", "other", "data.csv", file_contents
        )

        self.s3_adapter.upload_raw_data.assert_called_once_with(
            "some", "other", "2022-03-03T12:00:00-data.csv", file_contents
        )

    def test_list_raw_files_from_domain_and_dataset(self):
        self.s3_adapter.list_raw_files.return_value = [
            "2022-01-01T12:00:00-my_first_file.csv",
            "2022-02-10T15:00:00-my_second_file.csv",
            "2022-03-03T16:00:00-my_third_file.csv",
        ]
        list_raw_files = self.data_service.list_raw_files("domain", "dataset")
        assert list_raw_files == [
            "2022-01-01T12:00:00-my_first_file.csv",
            "2022-02-10T15:00:00-my_second_file.csv",
            "2022-03-03T16:00:00-my_third_file.csv",
        ]
        self.s3_adapter.list_raw_files.assert_called_once_with("domain", "dataset")

    def test_raises_exception_when_no_raw_files_found_for_domain_and_dataset(self):
        self.s3_adapter.list_raw_files.return_value = []
        with pytest.raises(
            UserError,
            match="There are no uploaded files for the domain \\[domain\\] or dataset \\[dataset\\]",
        ):
            self.data_service.list_raw_files("domain", "dataset")

        self.s3_adapter.list_raw_files.assert_called_once_with("domain", "dataset")


class TestDatasetInfoRetrieval:
    def setup_method(self):
        self.s3_adapter = Mock()
        self.glue_adapter = Mock()
        self.query_adapter = Mock()
        self.protected_domain_service = Mock()
        self.valid_schema = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
                Column(
                    name="date",
                    partition_index=None,
                    data_type="date",
                    allow_null=False,
                    format="%d/%m/%Y",
                ),
            ],
        )
        self.data_service = DataService(
            self.s3_adapter,
            self.glue_adapter,
            self.query_adapter,
            self.protected_domain_service,
        )
        self.glue_adapter.get_table_last_updated_date.return_value = (
            "2022-03-01 11:03:49+00:00"
        )

    def test_get_schema_information(self):
        expected_schema = EnrichedSchema(
            metadata=EnrichedSchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
                number_of_rows=48718,
                number_of_columns=3,
                last_updated="2022-03-01 11:03:49+00:00",
            ),
            columns=[
                EnrichedColumn(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
                EnrichedColumn(
                    name="colname2",
                    partition_index=None,
                    data_type="object",
                    allow_null=False,
                ),
                EnrichedColumn(
                    name="date",
                    partition_index=None,
                    data_type="date",
                    allow_null=False,
                    format="%d/%m/%Y",
                    statistics={"max": "2021-07-01", "min": "2014-01-01"},
                ),
            ],
        )
        self.s3_adapter.find_schema.return_value = self.valid_schema
        self.query_adapter.query.return_value = pd.DataFrame(
            {
                "data_size": [48718],
                "max_date": ["2021-07-01"],
                "min_date": ["2014-01-01"],
            }
        )
        actual_schema = self.data_service.get_dataset_info("some", "other")

        self.query_adapter.query.assert_called_once_with(
            "some",
            "other",
            SQLQuery(
                select_columns=[
                    "count(*) as data_size",
                    "max(date) as max_date",
                    "min(date) as min_date",
                ]
            ),
        )

        assert actual_schema == expected_schema

    def test_get_schema_information_for_multiple_dates(self):
        valid_schema = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
                Column(
                    name="date",
                    partition_index=None,
                    data_type="date",
                    allow_null=False,
                    format="%d/%m/%Y",
                ),
                Column(
                    name="date2",
                    partition_index=None,
                    data_type="date",
                    allow_null=False,
                    format="%d/%m/%Y",
                ),
            ],
        )

        expected_schema = EnrichedSchema(
            metadata=EnrichedSchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
                number_of_rows=48718,
                number_of_columns=3,
                last_updated="2022-03-01 11:03:49+00:00",
            ),
            columns=[
                EnrichedColumn(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                ),
                EnrichedColumn(
                    name="date",
                    partition_index=None,
                    data_type="date",
                    allow_null=False,
                    format="%d/%m/%Y",
                    statistics={"max": "2021-07-01", "min": "2014-01-01"},
                ),
                EnrichedColumn(
                    name="date2",
                    partition_index=None,
                    data_type="date",
                    allow_null=False,
                    format="%d/%m/%Y",
                    statistics={"max": "2020-07-01", "min": "2015-01-01"},
                ),
            ],
        )
        self.s3_adapter.find_schema.return_value = valid_schema
        self.query_adapter.query.return_value = pd.DataFrame(
            {
                "data_size": [48718],
                "max_date": ["2021-07-01"],
                "min_date": ["2014-01-01"],
                "max_date2": ["2020-07-01"],
                "min_date2": ["2015-01-01"],
            }
        )
        actual_schema = self.data_service.get_dataset_info("some", "other")

        self.query_adapter.query.assert_called_once_with(
            "some",
            "other",
            SQLQuery(
                select_columns=[
                    "count(*) as data_size",
                    "max(date) as max_date",
                    "min(date) as min_date",
                    "max(date2) as max_date2",
                    "min(date2) as min_date2",
                ]
            ),
        )

        assert actual_schema == expected_schema

    def test_get_schema_size_for_datasets_with_no_dates(self):
        valid_schema = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                )
            ],
        )
        expected_schema = EnrichedSchema(
            metadata=EnrichedSchemaMetadata(
                domain="some",
                dataset="other",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
                number_of_rows=48718,
                number_of_columns=1,
                last_updated="2022-03-01 11:03:49+00:00",
            ),
            columns=[
                EnrichedColumn(
                    name="colname1",
                    partition_index=0,
                    data_type="Int64",
                    allow_null=True,
                )
            ],
        )
        self.s3_adapter.find_schema.return_value = valid_schema
        self.query_adapter.query.return_value = pd.DataFrame({"data_size": [48718]})
        actual_schema = self.data_service.get_dataset_info("some", "other")

        self.query_adapter.query.assert_called_once_with(
            "some", "other", SQLQuery(select_columns=["count(*) as data_size"])
        )

        assert actual_schema == expected_schema

    def test_raises_error_when_schema_not_found(self):
        self.s3_adapter.find_schema.return_value = None

        with pytest.raises(SchemaNotFoundError):
            self.data_service.get_dataset_info("some", "other")
