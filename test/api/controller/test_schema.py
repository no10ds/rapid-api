from typing import Tuple, Dict
from unittest.mock import patch

from api.adapter.cognito_adapter import CognitoAdapter
from api.application.services.data_service import DataService
from api.application.services.delete_service import DeleteService
from api.application.services.schema_infer_service import SchemaInferService
from api.common.custom_exceptions import (
    SchemaError,
    ConflictError,
    CrawlerCreateFailsError,
    UserGroupCreationError,
    ProtectedDomainDoesNotExistError,
)
from api.domain.schema import Schema, Column
from api.domain.schema_metadata import Owner, SchemaMetadata
from test.api.controller.controller_test_utils import BaseClientTest


class TestSchemaUpload(BaseClientTest):
    @patch.object(DataService, "upload_schema")
    def test_calls_services_successfully(
        self,
        mock_upload_schema,
    ):
        request_body, expected_schema = self._generate_schema()

        mock_upload_schema.return_value = "some-thing.json"

        response = self.client.post(
            "/schema", json=request_body, headers={"Authorization": "Bearer test-token"}
        )

        mock_upload_schema.assert_called_once_with(expected_schema)

        assert response.status_code == 201
        assert response.json() == {"uploaded": "some-thing.json"}

    def test_return_400_pydantic_error(self):
        request_body = {
            "metadata": {"tags": {"tag1": "value1", "tag2": "value2"}},
            "columns": [
                {
                    "name": "colname1",
                    "partition_index": None,
                    "data_type": "number",
                    "allow_null": True,
                },
            ],
        }

        response = self.client.post(
            "/schema", json=request_body, headers={"Authorization": "Bearer test-token"}
        )

        assert response.status_code == 400
        assert response.json() == {
            "details": [
                "metadata: domain -> field required",
                "metadata: dataset -> field required",
                "metadata: sensitivity -> field required",
            ]
        }

    @patch.object(DataService, "upload_schema")
    def test_returns_409_when_schema_already_exists(self, mock_upload_schema):
        request_body, expected_schema = self._generate_schema()
        mock_upload_schema.side_effect = ConflictError("Error message")
        response = self.client.post(
            "/schema", json=request_body, headers={"Authorization": "Bearer test-token"}
        )

        assert response.status_code == 409
        assert response.json() == {"details": "Error message"}

    @patch.object(DataService, "upload_schema")
    def test_returns_400_when_invalid_schema(self, mock_upload_schema):
        request_body, expected_schema = self._generate_schema()
        mock_upload_schema.side_effect = SchemaError("Error message")
        response = self.client.post(
            "/schema", json=request_body, headers={"Authorization": "Bearer test-token"}
        )

        assert response.status_code == 400
        assert response.json() == {"details": "Error message"}

    @patch.object(CognitoAdapter, "delete_user_groups")
    @patch.object(CognitoAdapter, "create_user_groups")
    @patch.object(DeleteService, "delete_schema")
    @patch.object(DataService, "upload_schema")
    def test_returns_500_schema_deletion_if_crawler_creation_fails(
        self,
        mock_upload_schema,
        mock_delete_schema,
        mock_create_user_groups,
        mock_delete_user_groups,
    ):
        request_body, _ = self._generate_schema()

        mock_upload_schema.return_value = "some-thing.json"
        mock_create_user_groups.return_value = None
        mock_upload_schema.side_effect = CrawlerCreateFailsError(
            "Crawler creation error"
        )

        response = self.client.post(
            "/schema", json=request_body, headers={"Authorization": "Bearer test-token"}
        )

        assert response.status_code == 500
        assert response.json() == {"details": "Crawler creation error"}

        mock_delete_schema.assert_called_once_with("some", "thing", "PUBLIC")
        mock_delete_user_groups.assert_called_once_with("some", "thing")

    @patch.object(DeleteService, "delete_schema")
    @patch.object(DataService, "upload_schema")
    def test_returns_500_schema_deletion_if_user_group_creation_fails(
        self, mock_upload_schema, mock_delete_schema
    ):
        request_body, _ = self._generate_schema()

        mock_upload_schema.side_effect = UserGroupCreationError(
            "User group creation error"
        )

        response = self.client.post(
            "/schema", json=request_body, headers={"Authorization": "Bearer test-token"}
        )

        assert response.status_code == 500
        assert response.json() == {"details": "User group creation error"}

        mock_delete_schema.assert_called_once_with("some", "thing", "PUBLIC")

    @patch.object(DataService, "upload_schema")
    def test_returns_500_if_protected_domain_does_not_exist(
        self,
        mock_upload_schema,
    ):
        request_body, _ = self._generate_schema()

        mock_upload_schema.side_effect = ProtectedDomainDoesNotExistError(
            "Protected domain error"
        )

        response = self.client.post(
            "/schema", json=request_body, headers={"Authorization": "Bearer test-token"}
        )

        assert response.status_code == 500
        assert response.json() == {"details": "Protected domain error"}

    def _generate_schema(self) -> Tuple[Dict, Schema]:
        request_body = {
            "metadata": {
                "domain": "some",
                "dataset": "thing",
                "sensitivity": "PUBLIC",
                "owners": [{"name": "owner", "email": "owner@email.com"}],
                "key_value_tags": {"tag1": "value1", "tag2": "value2"},
                "key_only_tags": ["tag3", "tag4"],
            },
            "columns": [
                {
                    "name": "colname1",
                    "partition_index": None,
                    "data_type": "number",
                    "allow_null": True,
                },
                {
                    "name": "colname2",
                    "partition_index": 0,
                    "data_type": "str",
                    "allow_null": False,
                },
            ],
        }
        expected_schema = Schema(
            metadata=SchemaMetadata(
                domain="some",
                dataset="thing",
                sensitivity="PUBLIC",
                key_value_tags={"tag1": "value1", "tag2": "value2"},
                key_only_tags=["tag3", "tag4"],
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=None,
                    data_type="number",
                    allow_null=True,
                ),
                Column(
                    name="colname2",
                    partition_index=0,
                    data_type="str",
                    allow_null=False,
                ),
            ],
        )
        return request_body, expected_schema


class TestSchemaGeneration(BaseClientTest):
    @patch.object(SchemaInferService, "infer_schema")
    def test_returns_schema_from_a_csv_file(self, mock_infer_schema):
        expected_response = Schema(
            metadata=SchemaMetadata(
                domain="mydomain",
                dataset="mydataset",
                sensitivity="PUBLIC",
                owners=[Owner(name="owner", email="owner@email.com")],
            ),
            columns=[
                Column(
                    name="colname1",
                    partition_index=None,
                    data_type="object",
                    allow_null=True,
                    format=None,
                ),
                Column(
                    name="colname2",
                    partition_index=None,
                    data_type="Int64",
                    allow_null=True,
                    format=None,
                ),
            ],
        )
        file_content = b"colname1,colname2\nsomething,123\notherthing,456\n\n"
        file_name = "filename.csv"
        mock_infer_schema.return_value = expected_response

        response = self.client.post(
            "/schema/PUBLIC/mydomain/mydataset/generate",
            files={"file": (file_name, file_content, "text/csv")},
            headers={"Authorization": "Bearer test-token"},
        )
        mock_infer_schema.assert_called_once_with(
            "mydomain", "mydataset", "PUBLIC", file_content
        )

        assert response.status_code == 200
        assert response.json() == expected_response

    @patch.object(SchemaInferService, "infer_schema")
    def test_bad_request_when_schema_is_invalid(self, mock_infer_schema):
        file_content = b"colname1,colname2\nsomething,123\notherthing,456\n\n"
        file_name = "filename.csv"
        error_message = "The schema is wrong"
        mock_infer_schema.side_effect = SchemaError(error_message)

        response = self.client.post(
            "/schema/PUBLIC/mydomain/mydataset/generate",
            files={"file": (file_name, file_content, "text/csv")},
            headers={"Authorization": "Bearer test-token"},
        )
        mock_infer_schema.assert_called_once_with(
            "mydomain", "mydataset", "PUBLIC", file_content
        )

        assert response.status_code == 400
        assert response.json() == {"details": error_message}
