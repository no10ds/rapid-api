import json
from abc import ABC

import boto3
import requests
from requests.auth import HTTPBasicAuth

from api.common.config.aws import DATA_BUCKET, DOMAIN_NAME
from api.common.config.constants import CONTENT_ENCODING
from test.e2e.e2e_test_utils import get_secret, AuthenticationFailedError


class BaseJourneyTest(ABC):
    s3_client = boto3.client("s3")

    base_url = f"https://{DOMAIN_NAME}"
    datasets_url = f"{base_url}/datasets"

    data_directory = "data/test_e2e"
    raw_data_directory = "raw_data/test_e2e"

    filename = "test_journey_file.csv"

    data_filepath = f"{data_directory}"
    raw_data_filepath = f"{raw_data_directory}"

    def upload_dataset_url(self, domain: str, dataset: str) -> str:
        return f"{self.datasets_url}/{domain}/{dataset}"

    def query_dataset_url(self, domain: str, dataset: str) -> str:
        return f"{self.datasets_url}/{domain}/{dataset}/query"

    def info_dataset_url(self, domain: str, dataset: str) -> str:
        return f"{self.datasets_url}/{domain}/{dataset}/info"

    def list_dataset_files_url(self, domain: str, dataset: str) -> str:
        return f"{self.datasets_url}/{domain}/{dataset}/files"

    def delete_data_url(self, domain: str, dataset: str, filename: str) -> str:
        return f"{self.datasets_url}/{domain}/{dataset}/{filename}"


class TestUnauthenticatedJourneys(BaseJourneyTest):
    def test_http_request_is_redirected_to_https(self):
        response = requests.get(f"https://{DOMAIN_NAME}")
        assert f"https://{DOMAIN_NAME}" in response.url

    def test_status_always_accessible(self):
        api_url = f"{self.base_url}/status"
        response = requests.get(api_url)
        assert response.status_code == 200

    def test_query_is_unauthorised_when_no_token_provided(self):
        url = self.query_dataset_url("mydomain", "unknowndataset")
        response = requests.post(url)
        assert response.status_code == 401

    def test_upload_is_unauthorised_when_no_token_provided(self):
        files = {"file": (self.filename, open("./test/e2e/" + self.filename, "rb"))}
        url = self.upload_dataset_url("test_e2e", "upload")
        response = requests.post(url, files=files)
        assert response.status_code == 401

    def test_list_is_unauthorised_when_no_token_provided(self):
        response = requests.post(self.datasets_url)
        assert response.status_code == 401


class TestUnauthorisedJourney(BaseJourneyTest):
    token_url = f"https://{DOMAIN_NAME}/oauth2/token"
    credentials = get_secret(
        secret_name="E2E_TEST_COGNITO_APP_CLIENT_ID_AND_SECRET"  # pragma: allowlist secret
    )
    cognito_client_id = credentials["CLIENT_ID"]
    cognito_client_secret = credentials["CLIENT_SECRET"]  # pragma: allowlist secret

    access_token = None

    def setup_class(self):
        auth = HTTPBasicAuth(self.cognito_client_id, self.cognito_client_secret)

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.cognito_client_id,
            "scope": f"https://{DOMAIN_NAME}/WRITE_ALL",
        }

        response = requests.post(
            self.token_url, auth=auth, headers=headers, json=payload
        )

        if response.status_code != 200:
            raise AuthenticationFailedError(f"{response.status_code}")

        self.token = json.loads(response.content.decode(CONTENT_ENCODING))[
            "access_token"
        ]

    def generate_auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def test_query_existing_dataset_when_not_authorised_to_read(self):
        url = self.query_dataset_url("test_e2e", "query")
        response = requests.post(url, headers=self.generate_auth_headers())
        assert response.status_code == 401

    def test_existing_dataset_info_when_not_authorised_to_read(self):
        url = self.info_dataset_url("test_e2e", "query")
        response = requests.get(url, headers=self.generate_auth_headers())
        assert response.status_code == 401

    def test_delete_file_when_not_authorised_to_delete(self):
        url = self.delete_data_url("test_e2e", "delete", "test_journey_file.csv")
        response = requests.delete(url, headers=self.generate_auth_headers())
        assert response.status_code == 401


class TestAuthenticatedJourneys(BaseJourneyTest):
    token_url = f"https://{DOMAIN_NAME}/oauth2/token"
    credentials = get_secret(
        secret_name="E2E_TEST_COGNITO_APP_CLIENT_ID_AND_SECRET"  # pragma: allowlist secret
    )
    cognito_client_id = credentials["CLIENT_ID"]
    cognito_client_secret = credentials["CLIENT_SECRET"]  # pragma: allowlist secret

    print(cognito_client_id)

    access_token = None

    def setup_class(self):
        auth = HTTPBasicAuth(self.cognito_client_id, self.cognito_client_secret)

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        payload = {
            "grant_type": "client_credentials",
            "client_id": self.cognito_client_id,
            "scope": f"https://{DOMAIN_NAME}/READ_ALL https://{DOMAIN_NAME}/WRITE_ALL",
        }

        response = requests.post(
            self.token_url, auth=auth, headers=headers, json=payload
        )

        if response.status_code != 200:
            raise AuthenticationFailedError(f"{response.status_code}")

        self.token = json.loads(response.content.decode(CONTENT_ENCODING))[
            "access_token"
        ]

        self.s3_client.put_object(
            Bucket=DATA_BUCKET,
            Key=f"{self.raw_data_filepath}/delete/{self.filename}",
            Body=open("./test/e2e/" + self.filename, "rb"),
        )

        self.s3_client.put_object(
            Bucket=DATA_BUCKET,
            Key=f"{self.data_filepath}/delete/{self.filename}",
            Body=open("./test/e2e/" + self.filename, "rb"),
        )

    def teardown_class(self):
        files = self.s3_client.list_objects_v2(
            Bucket=DATA_BUCKET, Prefix=f"{self.raw_data_filepath}/upload"
        )

        files_to_delete = [
            file["Key"].rsplit("/", 1)[-1]
            for file in files["Contents"]
            if file["Key"].endswith(".csv")
        ]

        filepaths_to_delete = []
        for filename in files_to_delete:
            filepaths_to_delete.append(
                {"Key": f"{self.raw_data_filepath}/upload/{filename}"}
            )
            filepaths_to_delete.append(
                {"Key": f"{self.data_filepath}/upload/{filename}"}
            )

        self.s3_client.delete_objects(
            Bucket=DATA_BUCKET, Delete={"Objects": filepaths_to_delete}
        )

    def generate_auth_headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def test_query_non_existing_dataset_when_authorised(self):
        url = self.query_dataset_url("mydomain", "unknowndataset")
        response = requests.post(url, headers=self.generate_auth_headers())
        assert response.status_code == 400

    def test_upload_when_authorised(self):
        files = {"file": (self.filename, open("./test/e2e/" + self.filename, "rb"))}
        url = self.upload_dataset_url("test_e2e", "upload")
        response = requests.post(url, headers=self.generate_auth_headers(), files=files)
        assert response.status_code == 201

    def test_list_when_authorised(self):
        response = requests.post(
            self.datasets_url,
            headers=self.generate_auth_headers(),
            json={"tags": {"test": "e2e"}},
        )
        assert response.status_code == 200

    def test_query_existing_dataset_when_authorised(self):
        url = self.query_dataset_url(domain="test_e2e", dataset="query")
        response = requests.post(url, headers=(self.generate_auth_headers()))
        assert response.status_code == 200

    def test_query_existing_dataset_as_csv_when_authorised(self):
        url = self.query_dataset_url(domain="test_e2e", dataset="query")
        headers = {
            "Accept": "text/csv",
            "Authorization": "Bearer " + self.token,
        }
        response = requests.post(url, headers=headers)
        assert response.status_code == 200

        assert (
            response.text
            == '"","year","month","case_type","region","offence_group","remand_status","value","source"\n'
            + '0,"2017","7","3. Committed for sentence","North West","05: Criminal damage and arson","bail","89","XHIBIT"\n'
            + '1,"2017","7","3. Committed for sentence","North West","04: Theft offences","unknown","167","XHIBIT"\n'
        )

    def test_get_existing_dataset_info_when_authorised(self):
        url = self.info_dataset_url(domain="test_e2e", dataset="query")
        response = requests.get(url, headers=(self.generate_auth_headers()))
        assert response.status_code == 200

    def test_fails_to_query_when_authorised_and_sql_injection_attempted(self):
        url = self.query_dataset_url(domain="test_e2e", dataset="query")
        body = {"filter": "';DROP TABLE test_e2e--"}
        response = requests.post(url, headers=(self.generate_auth_headers()), json=body)
        assert response.status_code == 403

    def test_delete_existing_data_when_authorised(self):
        url = self.list_dataset_files_url(domain="test_e2e", dataset="delete")
        response1 = requests.get(url, headers=(self.generate_auth_headers()))
        assert response1.status_code == 200

        response_list = json.loads(response1.text)
        assert self.filename in response_list

        url2 = self.delete_data_url(
            domain="test_e2e", dataset="delete", filename=response_list[0]
        )
        response2 = requests.delete(url2, headers=(self.generate_auth_headers()))

        assert response2.status_code == 204
