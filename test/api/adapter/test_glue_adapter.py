from unittest.mock import Mock, patch, ANY

import pytest
from botocore.exceptions import ClientError

from api.adapter.glue_adapter import GlueAdapter
from api.common.config.aws import (
    GLUE_TABLE_PRESENCE_CHECK_RETRY_COUNT,
    GLUE_CSV_CLASSIFIER,
    DATA_BUCKET,
)
from api.common.config.aws import RESOURCE_PREFIX
from api.common.custom_exceptions import (
    CrawlerCreateFailsError,
    CrawlerStartFailsError,
    CrawlerDeleteFailsError,
    GetCrawlerError,
    CrawlerIsNotReadyError,
    TableNotCreatedError,
)


class TestGlueAdapterCrawlerMethods:
    glue_boto_client = None

    def setup_method(self):
        self.glue_boto_client = Mock()
        self.glue_adapter = GlueAdapter(
            self.glue_boto_client,
            "GLUE_CATALOGUE_DB_NAME",
            "GLUE_CRAWLER_ROLE",
            "GLUE_CONNECTION_DB_NAME",
        )

    def test_create_crawler(self):
        self.glue_adapter.create_crawler(
            RESOURCE_PREFIX,
            "domain",
            "dataset",
            {"tag1": "value1", "tag2": "value2", "tag3": "value3"},
        )
        self.glue_boto_client.create_crawler.assert_called_once_with(
            Name=RESOURCE_PREFIX + "_crawler/domain/dataset",
            Role="GLUE_CRAWLER_ROLE",
            DatabaseName="GLUE_CATALOGUE_DB_NAME",
            TablePrefix="domain_",
            Classifiers=[GLUE_CSV_CLASSIFIER],
            Targets={
                "S3Targets": [
                    {
                        "Path": f"s3://{DATA_BUCKET}/data/domain/dataset/",
                        "ConnectionName": "GLUE_CONNECTION_DB_NAME",
                    },
                ]
            },
            Tags={
                "tag1": "value1",
                "tag2": "value2",
                "tag3": "value3",
            },
        )

    def test_create_crawler_fails_already_exists(self):
        self.glue_boto_client.create_crawler.side_effect = ClientError(
            error_response={"Error": {"Code": "AlreadyExistsException"}},
            operation_name="CreateCrawler",
        )

        with pytest.raises(CrawlerCreateFailsError):
            self.glue_adapter.create_crawler(RESOURCE_PREFIX, "domain", "dataset", {})

    def test_create_crawler_fails(self):
        self.glue_boto_client.create_crawler.side_effect = ClientError(
            error_response={"Error": {"Code": "SomethingElse"}},
            operation_name="CreateCrawler",
        )

        with pytest.raises(CrawlerCreateFailsError):
            self.glue_adapter.create_crawler(RESOURCE_PREFIX, "domain", "dataset", {})

    def test_start_crawler(self):
        self.glue_adapter.start_crawler(RESOURCE_PREFIX, "domain", "dataset")
        self.glue_boto_client.start_crawler.assert_called_once_with(
            Name=RESOURCE_PREFIX + "_crawler/domain/dataset"
        )

    def test_start_crawler_fails(self):
        self.glue_boto_client.start_crawler.side_effect = ClientError(
            error_response={"Error": {"Code": "SomethingElse"}},
            operation_name="StartCrawler",
        )

        with pytest.raises(CrawlerStartFailsError):
            self.glue_adapter.start_crawler(RESOURCE_PREFIX, "domain", "dataset")

    def test_delete_crawler(self):
        self.glue_adapter.delete_crawler(RESOURCE_PREFIX, "domain", "dataset")
        self.glue_boto_client.delete_crawler.assert_called_once_with(
            RESOURCE_PREFIX + "_crawler/domain/dataset"
        )

    def test_delete_crawler_fails(self):
        self.glue_boto_client.delete_crawler.side_effect = ClientError(
            error_response={"Error": {"Code": "SomethingElse"}},
            operation_name="DeleteCrawler",
        )

        with pytest.raises(CrawlerDeleteFailsError):
            self.glue_adapter.delete_crawler(RESOURCE_PREFIX, "domain", "dataset")

    def test_fails_to_check_if_crawler_is_running(self):
        self.glue_boto_client.get_crawler.side_effect = ClientError(
            error_response={"Error": {"Code": "SomeProblem"}},
            operation_name="GetCrawler",
        )

        with pytest.raises(GetCrawlerError):
            self.glue_adapter.check_crawler_is_ready(
                RESOURCE_PREFIX, "domain", "dataset"
            )

    def test_check_crawler_is_ready(self):
        self.glue_boto_client.get_crawler.return_value = {
            "Crawler": {
                "State": "READY",
            }
        }
        self.glue_adapter.check_crawler_is_ready(RESOURCE_PREFIX, "domain", "dataset")
        self.glue_boto_client.get_crawler.assert_called_once_with(
            Name=RESOURCE_PREFIX + "_crawler/domain/dataset"
        )

    def test_check_crawler_is_not_ready(self):
        for state in ["RUNNING", "STOPPING"]:
            self.glue_boto_client.get_crawler.return_value = {
                "Crawler": {
                    "State": state,
                }
            }
            with pytest.raises(CrawlerIsNotReadyError):
                self.glue_adapter.check_crawler_is_ready(
                    RESOURCE_PREFIX, "domain", "dataset"
                )

            self.glue_boto_client.get_crawler.assert_called_with(
                Name=RESOURCE_PREFIX + "_crawler/domain/dataset"
            )


class TestGlueAdapterCatalogTableMethods:
    glue_boto_client = None

    def setup_method(self):
        self.glue_boto_client = Mock()
        self.glue_adapter = GlueAdapter(
            self.glue_boto_client,
            "GLUE_CATALOGUE_DB_NAME",
            "GLUE_CRAWLER_ROLE",
            "GLUE_CONNECTION_DB_NAME",
        )

    @patch("api.adapter.glue_adapter.threading.Thread")
    def test_starts_thread_to_update_table_config_when_table_does_not_exist(
        self, mock_thread
    ):
        self.glue_boto_client.get_table.side_effect = ClientError(
            error_response={"Error": {"Code": "EntityNotFoundException"}},
            operation_name="GetTable",
        )

        self.glue_adapter.update_catalog_table_config("a-domain", "b-dataset")

        self.glue_boto_client.get_table.assert_called_once_with(
            DatabaseName="GLUE_CATALOGUE_DB_NAME", Name="a-domain_b-dataset"
        )
        mock_thread.assert_called_once_with(target=ANY, args=("a-domain_b-dataset",))

    @patch("api.adapter.glue_adapter.threading.Thread")
    def test_starts_thread_to_update_table_config_when_table_exists_but_not_correctly_configured(
        self, mock_thread
    ):
        self.glue_boto_client.get_table.return_value = {
            "Table": {
                "StorageDescriptor": {
                    "SerdeInfo": {
                        "SerializationLibrary": "INCORRECT",
                        "Parameters": {"quoteChar": "ALSO INCORRECT"},
                    }
                }
            }
        }

        self.glue_adapter.update_catalog_table_config("a-domain", "b-dataset")

        self.glue_boto_client.get_table.assert_called_once_with(
            DatabaseName="GLUE_CATALOGUE_DB_NAME", Name="a-domain_b-dataset"
        )
        mock_thread.assert_called_once_with(target=ANY, args=("a-domain_b-dataset",))
        assert mock_thread.call_args[1]["target"].__name__ == "update_table"

    @patch("api.adapter.glue_adapter.threading.Thread")
    def test_starts_thread_to_update_table_config_when_table_exists_but_no_relevant_config_exists(
        self, mock_thread
    ):
        self.glue_boto_client.get_table.return_value = {
            "Table": {
                "StorageDescriptor": {
                    "SerdeInfo": {
                        # Missing "SerializationLibrary" key
                        "Parameters": {
                            # Missing "quoteChar" key
                        }
                    }
                }
            }
        }

        self.glue_adapter.update_catalog_table_config("a-domain", "b-dataset")

        self.glue_boto_client.get_table.assert_called_once_with(
            DatabaseName="GLUE_CATALOGUE_DB_NAME", Name="a-domain_b-dataset"
        )
        mock_thread.assert_called_once_with(target=ANY, args=("a-domain_b-dataset",))
        assert mock_thread.call_args[1]["target"].__name__ == "update_table"

    @patch("api.adapter.glue_adapter.threading.Thread")
    def test_does_not_start_thread_to_update_table_config_when_correctly_configured_table_exists(
        self, mock_thread
    ):
        self.glue_boto_client.get_table.return_value = {
            "Table": {
                "StorageDescriptor": {
                    "SerdeInfo": {
                        "SerializationLibrary": "org.apache.hadoop.hive.serde2.OpenCSVSerde",
                        "Parameters": {"quoteChar": '"'},
                    }
                }
            }
        }

        self.glue_adapter.update_catalog_table_config("a-domain", "b-dataset")

        assert not mock_thread.called

    def test_updates_table_config_with_correct_serialisation_library_and_quote_character(
        self,
    ):
        original_table_config = {
            "Table": {
                "Name": 111,
                "Owner": 222,
                "LastAccessTime": 333,
                "Retention": 444,
                "PartitionKeys": 555,
                "TableType": 666,
                "Parameters": 777,
                "StorageDescriptor": {
                    "existing_key": 888,
                    "SerdeInfo": {
                        "SerializationLibrary": "INCORRECT",
                        "Parameters": {
                            "existing_param": 999,
                            "quoteChar": "ALSO INCORRECT",
                        },
                    },
                },
            }
        }

        altered_table_config = {
            "Name": 111,
            "Owner": 222,
            "LastAccessTime": 333,
            "Retention": 444,
            "PartitionKeys": 555,
            "TableType": 666,
            "Parameters": 777,
            "StorageDescriptor": {
                "existing_key": 888,
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.OpenCSVSerde",
                    "Parameters": {"existing_param": 999, "quoteChar": '"'},
                },
            },
        }

        result = self.glue_adapter.update_table_csv_parsing_config(
            original_table_config
        )

        assert result == altered_table_config

    def test_updates_table_with_altered_config(self):
        self.glue_boto_client.get_table.return_value = {
            "Table": {
                "Name": 111,
                "Owner": 222,
                "LastAccessTime": 333,
                "Retention": 444,
                "PartitionKeys": 555,
                "TableType": 666,
                "Parameters": 777,
                "StorageDescriptor": {
                    "existing_key": 888,
                    "SerdeInfo": {
                        "SerializationLibrary": "INCORRECT",
                        "Parameters": {
                            "existing_param": 999,
                            "quoteChar": "ALSO INCORRECT",
                        },
                    },
                },
            }
        }

        altered_table_config = {
            "Name": 111,
            "Owner": 222,
            "LastAccessTime": 333,
            "Retention": 444,
            "PartitionKeys": 555,
            "TableType": 666,
            "Parameters": 777,
            "StorageDescriptor": {
                "existing_key": 888,
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.OpenCSVSerde",
                    "Parameters": {"existing_param": 999, "quoteChar": '"'},
                },
            },
        }

        self.glue_adapter.update_table("some-table-name")

        self.glue_boto_client.update_table.assert_called_once_with(
            DatabaseName="GLUE_CATALOGUE_DB_NAME", TableInput=altered_table_config
        )

    def test_gets_table_when_created(self):
        table_config = {}
        self.glue_boto_client.get_table.return_value = table_config

        result = self.glue_adapter.get_table_when_created("some-name")

        assert result == table_config

    def test_gets_table_last_updated_date(self):
        table_config = {
            "Table": {
                "Name": "test_e2e",
                "DatabaseName": "rapid_catalogue_db",
                "Owner": "owner",
                "CreateTime": "2022-03-01 11:03:49+00:00",
                "UpdateTime": "2022-03-03 11:03:49+00:00",
                "LastAccessTime": "2022-03-02 11:03:49+00:00",
                "Retention": 0,
            }
        }
        self.glue_boto_client.get_table.return_value = table_config

        result = self.glue_adapter.get_table_last_updated_date("table_name")

        assert result == "2022-03-03 11:03:49+00:00"

    @patch("api.adapter.glue_adapter.sleep")
    def test_raises_error_when_table_does_not_exist_and_retries_exhausted(
        self, mock_sleep
    ):
        self.glue_boto_client.get_table.side_effect = ClientError(
            error_response={"Error": {"Code": "EntityNotFoundException"}},
            operation_name="GetTable",
        )

        with pytest.raises(
            TableNotCreatedError, match=r"\[some-name\] was not created after \d+s"
        ):
            self.glue_adapter.get_table_when_created("some-name")

        assert mock_sleep.call_count == GLUE_TABLE_PRESENCE_CHECK_RETRY_COUNT

    def test_updates_glue_table_with_relevant_config(self):
        table_name = "some-table"

        invalid_table_config = {
            "Table": {
                "Name": table_name,
                "Owner": 222,
                "LastAccessTime": 333,
                "Retention": 444,
                "PartitionKeys": 555,
                "TableType": 666,
                "Parameters": 777,
                "StorageDescriptor": {
                    "existing_key": 888,
                    "SerdeInfo": {
                        "SerializationLibrary": "INCORRECT",
                        "Parameters": {
                            "existing_param": 999,
                            "quoteChar": "ALSO INCORRECT",
                        },
                    },
                },
            }
        }

        altered_table_config = {
            "Name": table_name,
            "Owner": 222,
            "LastAccessTime": 333,
            "Retention": 444,
            "PartitionKeys": 555,
            "TableType": 666,
            "Parameters": 777,
            "StorageDescriptor": {
                "existing_key": 888,
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.OpenCSVSerde",
                    "Parameters": {"existing_param": 999, "quoteChar": '"'},
                },
            },
        }

        self.glue_boto_client.get_table.return_value = invalid_table_config

        self.glue_adapter.update_table(table_name)

        self.glue_boto_client.update_table.assert_called_once_with(
            DatabaseName="GLUE_CATALOGUE_DB_NAME", TableInput=altered_table_config
        )
