from fastapi import APIRouter
from fastapi import UploadFile, File, Security
from fastapi import status as http_status

from api.adapter.cognito_adapter import CognitoAdapter
from api.adapter.glue_adapter import GlueAdapter
from api.application.services.authorisation_service import protect_endpoint
from api.application.services.data_service import DataService
from api.application.services.delete_service import DeleteService
from api.application.services.schema_infer_service import SchemaInferService
from api.common.config.auth import Action
from api.common.custom_exceptions import (
    AWSServiceError,
    CrawlerCreateFailsError,
    UserGroupCreationError,
    ProtectedDomainDoesNotExistError,
)
from api.common.logger import AppLogger
from api.controller.utils import _response_body
from api.domain.schema import Schema
from api.common.config.aws import RESOURCE_PREFIX

data_service = DataService()
schema_infer_service = SchemaInferService()
glue_adapter = GlueAdapter()
delete_service = DeleteService()
cognito_adapter = CognitoAdapter()

schema_router = APIRouter(
    prefix="/schema",
    tags=["Schema"],
    responses={404: {"description": "Not found"}},
)


@schema_router.post("/{sensitivity}/{domain}/{dataset}/generate")
async def generate_schema(
    sensitivity: str, domain: str, dataset: str, file: UploadFile = File(...)
):
    """
    ## Generate schema

    In order to upload the dataset for the first time, you need to define its schema. This endpoint is provided for your
    convenience to generate a schema based on an existing dataset. Alternatively you can consult
    the [schema writing guide](https://github.com/no10ds/rapid-api/blob/main/docs/guides/usage/schema_creation.md) if you would like to create the schema yourself. You can then use the
    output of this endpoint in the Schema Upload endpoint.

    ### Inputs

    | Parameters    | Usage                                   | Example values               | Definition                 |
    |---------------|-----------------------------------------|------------------------------|----------------------------|
    | `sensitivity` | URL parameter                           | `PUBLIC, PRIVATE, PROTECTED` | sensitivity of the dataset |
    | `domain`      | URL parameter                           | `demo`                       | domain of the dataset      |
    | `dataset`     | URL parameter                           | `gapminder`                  | dataset title              |
    | `file`        | File in form data with key value `file` | `gapminder.csv`              | the dataset file itself    |

    ### Click  `Try it out` to use the endpoint

    """
    file_contents = await file.read()
    return schema_infer_service.infer_schema(
        domain, dataset, sensitivity, file_contents
    )


@schema_router.post(
    "",
    status_code=http_status.HTTP_201_CREATED,
    dependencies=[Security(protect_endpoint, scopes=[Action.DATA_ADMIN.value])],
)
async def upload_schema(schema: Schema):
    """
    ## Upload Schema

    When you have a schema definition you can use this endpoint to upload it. This will allow you to subsequently upload
    datasets that match the schema. If you do not yet have a schema definition, you can craft this yourself (see
    the [schema writing guide](https://github.com/no10ds/rapid-api/blob/main/docs/guides/usage/schema_creation.md)) or use the Schema Generation endpoint (see above).

    ### Inputs

    | Parameters    | Usage                                   | Example values               | Definition            |
    |---------------|-----------------------------------------|------------------------------|-----------------------|
    | schema        | JSON request body                       | see below                    | the schema definition |

    ### Accepted scopes

    In order to use this endpoint you need the `DATA_ADMIN` scope.

    ### Click  `Try it out` to use the endpoint
    """
    try:
        schema_file_name = data_service.upload_schema(schema)
        cognito_adapter.create_user_groups(schema.get_domain(), schema.get_dataset())
        glue_adapter.create_crawler(
            RESOURCE_PREFIX,
            schema.get_domain(),
            schema.get_dataset(),
            schema.get_tags(),
        )
        return _response_body(schema_file_name)
    except ProtectedDomainDoesNotExistError as error:
        _log_and_raise_error("Protected domain error", error.args[0])
    except UserGroupCreationError as error:
        _delete_uploaded_schema(schema)
        _log_and_raise_error("User group creation error", error.args[0])
    except CrawlerCreateFailsError as error:
        _delete_created_groups_and_schema(schema)
        _log_and_raise_error("Failed to create crawler", error.args[0])


def _delete_uploaded_schema(schema: Schema):
    delete_service.delete_schema(
        schema.get_domain(), schema.get_dataset(), schema.get_sensitivity()
    )


def _delete_created_groups_and_schema(schema: Schema):
    cognito_adapter.delete_user_groups(schema.get_domain(), schema.get_dataset())
    _delete_uploaded_schema(schema)


def _log_and_raise_error(log_message: str, error_message: str):
    AppLogger.error(f"{log_message}: {error_message}")
    raise AWSServiceError(message=error_message)
