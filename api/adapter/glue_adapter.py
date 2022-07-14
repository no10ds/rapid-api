import threading
from time import sleep
from typing import Dict

import boto3
from botocore.exceptions import ClientError

from api.common.config.aws import (
    AWS_REGION,
    GLUE_CATALOGUE_DB_NAME,
    GLUE_CRAWLER_ROLE,
    GLUE_CONNECTION_NAME,
    GLUE_QUOTE_CHAR,
    GLUE_CSV_CLASSIFIER,
    GLUE_CSV_SERIALISATION_LIBRARY,
    GLUE_TABLE_PRESENCE_CHECK_RETRY_COUNT,
    GLUE_TABLE_PRESENCE_CHECK_INTERVAL,
)
from api.common.custom_exceptions import (
    CrawlerCreateFailsError,
    CrawlerStartFailsError,
    CrawlerDeleteFailsError,
    GetCrawlerError,
    CrawlerIsNotReadyError,
    TableDoesNotExistError,
    TableNotCreatedError,
)
from api.common.logger import AppLogger
from api.domain.storage_metadata import StorageMetaData


class GlueAdapter:
    def __init__(
        self,
        glue_client=boto3.client("glue", region_name=AWS_REGION),
        glue_catalogue_db_name=GLUE_CATALOGUE_DB_NAME,
        glue_crawler_role=GLUE_CRAWLER_ROLE,
        glue_connection_name=GLUE_CONNECTION_NAME,
    ):
        self.glue_client = glue_client
        self.glue_catalogue_db_name = glue_catalogue_db_name
        self.glue_crawler_role = glue_crawler_role
        self.glue_connection_name = glue_connection_name

    def create_crawler(
        self, resource_prefix: str, domain: str, dataset: str, tags: Dict[str, str]
    ):
        data_store = StorageMetaData(domain, dataset)
        try:
            self.glue_client.create_crawler(
                Name=self._generate_crawler_name(resource_prefix, domain, dataset),
                Role=self.glue_crawler_role,
                DatabaseName=self.glue_catalogue_db_name,
                TablePrefix=data_store.glue_table_prefix(),
                Classifiers=[
                    GLUE_CSV_CLASSIFIER,
                ],
                Targets={
                    "S3Targets": [
                        {
                            "Path": data_store.s3_path(),
                            "ConnectionName": self.glue_connection_name,
                        },
                    ]
                },
                Tags=tags,
            )
        except ClientError as error:
            self._handle_crawler_create_error(error)

    def start_crawler(self, resource_prefix: str, domain: str, dataset: str):
        try:
            self.glue_client.start_crawler(
                Name=self._generate_crawler_name(resource_prefix, domain, dataset)
            )
        except ClientError:
            raise CrawlerStartFailsError("Failed to start crawler")

    def delete_crawler(self, resource_prefix: str, domain: str, dataset: str):
        try:
            self.glue_client.delete_crawler(
                self._generate_crawler_name(resource_prefix, domain, dataset)
            )
        except ClientError:
            raise CrawlerDeleteFailsError("Failed to delete crawler")

    def check_crawler_is_ready(self, resource_prefix: str, domain: str, dataset: str):
        if self._get_crawler_state(resource_prefix, domain, dataset) != "READY":
            raise CrawlerIsNotReadyError(
                f"Crawler is not ready for resource_prefix={resource_prefix}, domain={domain} and dataset={dataset}"
            )

    def update_catalog_table_config(self, domain: str, dataset: str):
        table_name = StorageMetaData(domain, dataset).glue_table_name()
        if self._table_needs_reconfiguration(table_name):
            threading.Thread(target=self.update_table, args=(table_name,)).start()

    def update_table(self, table_name: str):
        table = self.get_table_when_created(table_name)
        updated_definition = self.update_table_csv_parsing_config(table)
        self.glue_client.update_table(
            DatabaseName=self.glue_catalogue_db_name, TableInput=updated_definition
        )
        AppLogger.info(f"Glue table [{table_name}] updated with CSV parsing config")

    def get_table_when_created(self, table_name: str) -> Dict:
        for _ in range(GLUE_TABLE_PRESENCE_CHECK_RETRY_COUNT):
            try:
                return self._get_table(table_name)
            except TableDoesNotExistError:
                AppLogger.info(
                    f"Waiting {GLUE_TABLE_PRESENCE_CHECK_INTERVAL}s for table [{table_name}] to be created"
                )
                sleep(GLUE_TABLE_PRESENCE_CHECK_INTERVAL)
                continue
        raise TableNotCreatedError(
            f"[{table_name}] was not created after {GLUE_TABLE_PRESENCE_CHECK_RETRY_COUNT * GLUE_TABLE_PRESENCE_CHECK_INTERVAL}s"
        )  # noqa: E501

    def get_table_last_updated_date(self, table_name) -> str:
        table = self._get_table(table_name)
        return str(table["Table"]["UpdateTime"])

    def update_table_csv_parsing_config(self, response: Dict) -> Dict:
        table_storage_desc = response["Table"]["StorageDescriptor"]
        table_storage_desc["SerdeInfo"] = {
            **table_storage_desc["SerdeInfo"],
            "SerializationLibrary": GLUE_CSV_SERIALISATION_LIBRARY,
            "Parameters": {
                **table_storage_desc["SerdeInfo"]["Parameters"],
                "quoteChar": GLUE_QUOTE_CHAR,
            },
        }

        return {
            "Name": response["Table"]["Name"],
            "Owner": response["Table"]["Owner"],
            "LastAccessTime": response["Table"]["LastAccessTime"],
            "Retention": response["Table"]["Retention"],
            "PartitionKeys": response["Table"]["PartitionKeys"],
            "TableType": response["Table"]["TableType"],
            "Parameters": response["Table"]["Parameters"],
            "StorageDescriptor": table_storage_desc,
        }

    def _get_crawler_state(
        self, resource_prefix: str, domain: str, dataset: str
    ) -> str:
        try:
            response = self.glue_client.get_crawler(
                Name=self._generate_crawler_name(resource_prefix, domain, dataset)
            )
            return response["Crawler"]["State"]
        except ClientError:
            raise GetCrawlerError(
                f"Failed to get crawler state resource_prefix={resource_prefix}, domain = {domain} dataset = {dataset}"
            )

    def _generate_crawler_name(
        self, resource_prefix: str, domain: str, dataset: str
    ) -> str:
        return resource_prefix + "_crawler/" + domain + "/" + dataset

    def _handle_crawler_create_error(self, error: ClientError):
        if error.response["Error"]["Code"] == "AlreadyExistsException":
            raise CrawlerCreateFailsError("Crawler already exists with same name")
        else:
            raise CrawlerCreateFailsError("Crawler creation error")

    def _table_needs_reconfiguration(self, table_name: str) -> bool:
        try:
            table_config = self._get_table(table_name)
        except TableDoesNotExistError:
            return True
        return not self._table_configured_correctly(table_config)

    def _table_configured_correctly(self, table_config: Dict) -> bool:
        try:
            serialisation_lib = table_config["Table"]["StorageDescriptor"]["SerdeInfo"][
                "SerializationLibrary"
            ]
            quote_char = table_config["Table"]["StorageDescriptor"]["SerdeInfo"][
                "Parameters"
            ]["quoteChar"]
        except KeyError:
            return False

        quote_char_correct = quote_char == GLUE_QUOTE_CHAR
        lib_correct = serialisation_lib == GLUE_CSV_SERIALISATION_LIBRARY

        return quote_char_correct and lib_correct

    def _get_table(self, table_name: str) -> Dict:
        try:
            table = self.glue_client.get_table(
                DatabaseName=self.glue_catalogue_db_name, Name=table_name
            )
            return table
        except ClientError as error:
            if error.response["Error"]["Code"] == "EntityNotFoundException":
                raise TableDoesNotExistError(f"The table [{table_name}] does not exist")
