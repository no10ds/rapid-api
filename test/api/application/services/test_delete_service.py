from unittest.mock import Mock

import pytest

from api.application.services.delete_service import DeleteService
from api.common.config.aws import RESOURCE_PREFIX
from api.common.custom_exceptions import (
    CrawlerIsNotReadyError,
    CrawlerStartFailsError,
    UserError,
)


class TestDeleteService:
    def setup_method(self):
        self.s3_adapter = Mock()
        self.glue_adapter = Mock()
        self.delete_service = DeleteService(self.s3_adapter, self.glue_adapter)

    def test_delete_schema(self):
        self.delete_service.delete_schema("domain", "dataset", "PUBLIC")

        self.s3_adapter.delete_schema.assert_called_once_with(
            "domain", "dataset", "PUBLIC"
        )

    def test_delete_file_when_crawler_is_ready(self):
        self.delete_service.delete_dataset_file(
            RESOURCE_PREFIX, "domain", "dataset", "2022-01-01T00:00:00-file.csv"
        )
        self.s3_adapter.find_raw_file.assert_called_once_with(
            "domain", "dataset", "2022-01-01T00:00:00-file.csv"
        )
        self.glue_adapter.check_crawler_is_ready.assert_called_once_with(
            RESOURCE_PREFIX, "domain", "dataset"
        )
        self.s3_adapter.delete_dataset_files.assert_called_once_with(
            "domain", "dataset", "2022-01-01T00:00:00-file.csv"
        )
        self.glue_adapter.start_crawler.assert_called_once_with(
            RESOURCE_PREFIX, "domain", "dataset"
        )

    def test_delete_file_when_file_does_not_exist(self):
        self.s3_adapter.find_raw_file.side_effect = UserError("Some message")

        with pytest.raises(UserError):
            self.delete_service.delete_dataset_file(
                RESOURCE_PREFIX, "domain", "dataset", "2022-01-01T00:00:00-file.csv"
            )

        self.s3_adapter.find_raw_file.assert_called_once_with(
            "domain", "dataset", "2022-01-01T00:00:00-file.csv"
        )

    def test_delete_file_when_crawler_is_not_ready_before_deletion(self):
        self.glue_adapter.check_crawler_is_ready.side_effect = CrawlerIsNotReadyError(
            "Not ready, try later"
        )

        with pytest.raises(CrawlerIsNotReadyError):
            self.delete_service.delete_dataset_file(
                RESOURCE_PREFIX, "domain", "dataset", "2022-01-01T00:00:00-file.csv"
            )

        self.s3_adapter.find_raw_file.assert_called_once_with(
            "domain", "dataset", "2022-01-01T00:00:00-file.csv"
        )
        self.glue_adapter.check_crawler_is_ready.assert_called_once_with(
            RESOURCE_PREFIX, "domain", "dataset"
        )
        assert (
            not self.s3_adapter.delete_dataset_files.called
        ), "The delete method should not be called due to crawler fail error"

    def test_delete_file_when_crawler_is_not_ready_after_deletion(self):
        self.glue_adapter.start_crawler.side_effect = CrawlerStartFailsError(
            "Not ready, try later"
        )

        with pytest.raises(CrawlerStartFailsError):
            self.delete_service.delete_dataset_file(
                RESOURCE_PREFIX, "domain", "dataset", "2022-01-01T00:00:00-file.csv"
            )

        self.s3_adapter.find_raw_file.assert_called_once_with(
            "domain", "dataset", "2022-01-01T00:00:00-file.csv"
        )
        self.glue_adapter.check_crawler_is_ready.assert_called_once_with(
            RESOURCE_PREFIX, "domain", "dataset"
        )
        self.s3_adapter.delete_dataset_files.assert_called_once_with(
            "domain", "dataset", "2022-01-01T00:00:00-file.csv"
        )
        self.glue_adapter.start_crawler.assert_called_once_with(
            RESOURCE_PREFIX, "domain", "dataset"
        )

    @pytest.mark.parametrize(
        "filename",
        [
            "../filename.csv",
            ".",
            " ",
            "../../.",
            "../..",
            "..file",
            "hello/../domain",
            "2022-01-01T00:00:00-fiLe0192/../tf.csv",
            "2022-01-01T00:00:00-fiLe.csv/../tf.csv",
            "2022-01-01T00:00:00-fiLe.csv/..",
        ],
    )
    def test_delete_filename_error_for_bad_filenames(self, filename: str):
        with pytest.raises(UserError, match=f"Invalid file name \\[{filename}\\]"):
            self.delete_service.delete_dataset_file(
                RESOURCE_PREFIX, "domain", "dataset", filename
            )
