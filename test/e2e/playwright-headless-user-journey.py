from clean_athena import athena_query
from s3_utils import (
    get_file_names,
    cleanup_query_files,
    cleanup_data_files,
    cleanup_raw_files,
)
from e2e_test_utils import get_secret
from playwright.sync_api import Playwright, sync_playwright
import sys
import os
from time import sleep

sys.path.append(os.path.join(os.path.dirname(__file__), "../../"))


params = {
    "region": os.environ["AWS_REGION"],
    "data_bucket": os.environ["DATA_BUCKET"],
    "query_bucket": os.environ["QUERY_BUCKET"],
    "kmskey": os.environ["KMS_KEY"],
    "database": os.environ["DATABASE"],
    "account_id": os.environ["AWS_ACCOUNT"],
    "raw_data_path": "raw_data/playwright/playwright01/",
    "data_path": "data/playwright/playwright01/",
    "query_path": "playwright01/",
    "catalog": "AwsDataCatalog",
}


def run(playwright: Playwright) -> None:
    browser = playwright.chromium.launch(headless=True, slow_mo=500)
    context = browser.new_context()

    credentials = get_secret(
        secret_name="DEV_NO10DS_E2E_TEST_COGNITO_APP_CLIENT_ID_AND_SECRET"  # pragma: allowlist secret
    )
    cognito_client_id = credentials["CLIENT_ID"]
    cognito_client_secret = credentials["CLIENT_SECRET"]  # pragma: allowlist secret

    print("Starting Playwright Headless User Journey")
    # Open new page
    page = context.new_page()
    # Go to http://service-image:8000/docs
    page.goto("http://service-image:8000/docs")
    # Click button:has-text("Authorize")
    page.locator('button:has-text("Authorize")').click()
    # Click input[type="text"]
    page.locator('input[type="text"]').click()
    # Fill input[type="text"]
    page.locator('input[type="text"]').fill(cognito_client_id)
    # Click input[type="password"]
    page.locator('input[type="password"]').click()
    # Click input[type="password"]
    page.locator('input[type="password"]').click()
    # Fill input[type="password"]
    page.locator('input[type="password"]').fill(cognito_client_secret)
    # Click text=Authorize >> nth=1
    page.locator("text=Authorize").nth(1).click()
    # Click text=Close
    page.locator("text=Close").click()
    # Click text=POST/schema/{sensitivity}/{domain}/{dataset}/generateGenerate Schema
    page.locator(
        "text=POST/schema/{sensitivity}/{domain}/{dataset}/generateGenerate Schema"
    ).click()
    page.wait_for_url(
        "http://service-image:8000/docs#/Schema/generate_schema_schema__sensitivity___domain___dataset__generate_post"
    )
    # Click button:has-text("Try it out")
    page.locator('button:has-text("Try it out")').click()
    # Click [placeholder="sensitivity"]
    page.locator('[placeholder="sensitivity"]').click()
    # Fill [placeholder="sensitivity"]
    page.locator('[placeholder="sensitivity"]').fill("PUBLIC")
    # Press Tab
    page.locator('[placeholder="sensitivity"]').press("Tab")
    # Fill [placeholder="domain"]
    page.locator('[placeholder="domain"]').fill("playwright")
    # Press Tab
    page.locator('[placeholder="domain"]').press("Tab")
    # Fill [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').fill("playwright01")
    # Click input[type="file"]
    page.locator('input[type="file"]').click()
    # Upload test/e2e/test_journey_file.csv
    page.locator('input[type="file"]').set_input_files("test/e2e/test_journey_file.csv")
    # Click text=Execute
    page.locator("text=Execute").click()
    # Click .highlight-code > .copy-to-clipboard > button
    page.locator(".highlight-code > .copy-to-clipboard > button").click()
    # Click text=POST/schema/{sensitivity}/{domain}/{dataset}/generateGenerate Schema
    page.locator(
        "text=POST/schema/{sensitivity}/{domain}/{dataset}/generateGenerate Schema"
    ).click()
    page.wait_for_url("http://service-image:8000/docs#/")
    # Click text=POST/schemaUpload Schema
    page.locator("text=POST/schemaUpload Schema").click()
    page.wait_for_url(
        "http://service-image:8000/docs#/Schema/upload_schema_schema_post"
    )
    # Click button:has-text("Try it out")
    page.locator('button:has-text("Try it out")').click()
    # Click textarea
    page.locator("textarea").click()
    # Fill textarea
    page.locator("textarea").fill(
        '{\n  "metadata": {\n    "domain": "string",\n    "dataset": "string",\n    "sensitivity": "string",\n    "key_value_tags": {},\n    "key_only_tags": [],\n    "owners": [\n      {\n        "name": "string",\n        "email": "user@example.com"\n      }\n    ],\n    "update_behaviour": "APPEND"\n  },\n  "columns":     {\n      "name": "string",\n      "partition_index": 0,\n      "data_type": "string",\n      "allow_null": true,\n      "format": "string"\n    }\n  ]\n}'
    )
    # Click textarea
    page.locator("textarea").click()
    # Press a with modifiers
    page.locator("textarea").press("Control+a")
    # Fill textarea
    page.locator("textarea").fill(
        '{\n  "metadata": {\n    "domain": "playwright",\n    "dataset": "playwright01",\n    "sensitivity": "PUBLIC",\n    "key_value_tags": {},\n    "key_only_tags": [],\n    "owners": [\n      {\n        "name": "playwright",\n        "email": "playwright@email.com"\n      }\n    ],\n    "update_behaviour": "APPEND"\n  },\n  "columns": [\n    {\n      "name": "year",\n      "partition_index": null,\n      "data_type": "Int64",\n      "allow_null": true,\n      "format": null\n    },\n    {\n      "name": "month",\n      "partition_index": null,\n      "data_type": "Int64",\n      "allow_null": true,\n      "format": null\n    },\n    {\n      "name": "destination",\n      "partition_index": null,\n      "data_type": "object",\n      "allow_null": true,\n      "format": null\n    },\n    {\n      "name": "arrival",\n      "partition_index": null,\n      "data_type": "object",\n      "allow_null": true,\n      "format": null\n    },\n    {\n      "name": "type",\n      "partition_index": null,\n      "data_type": "object",\n      "allow_null": true,\n      "format": null\n    },\n    {\n      "name": "status",\n      "partition_index": null,\n      "data_type": "object",\n      "allow_null": true,\n      "format": null\n    }\n  ]\n}'
    )
    # Click textarea
    page.locator("textarea").click()
    # Click textarea
    page.locator("textarea").click()
    # Double click textarea
    page.locator("textarea").dblclick()
    # Click textarea
    page.locator("textarea").click()
    # Click textarea
    page.locator("textarea").click()
    # Click textarea
    page.locator("textarea").click()
    # Click textarea
    page.locator("textarea").click()
    # Click textarea
    page.locator("textarea").click()
    # Click text=Execute
    page.locator("text=Execute").click()
    # Click text=POST/schemaUpload Schema
    page.locator("text=POST/schemaUpload Schema").click()
    page.wait_for_url("http://service-image:8000/docs#/")
    # Click text=POST/datasets/{domain}/{dataset}Upload Data
    page.locator("text=POST/datasets/{domain}/{dataset}Upload Data").click()
    page.wait_for_url(
        "http://service-image:8000/docs#/Datasets/upload_data_datasets__domain___dataset__post"
    )
    # Click button:has-text("Try it out")
    page.locator('button:has-text("Try it out")').click()
    # Click [placeholder="domain"]
    page.locator('[placeholder="domain"]').click()
    # Fill [placeholder="domain"]
    page.locator('[placeholder="domain"]').fill("playwright")
    # Click [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').click()
    # Fill [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').fill("playwright01")
    # Click input[type="file"]
    page.locator('input[type="file"]').click()
    # Upload test/e2e/test_journey_file.csv
    page.locator('input[type="file"]').set_input_files("test/e2e/test_journey_file.csv")
    # Click text=Execute
    page.locator("text=Execute").click()
    # Click text=POST/datasets/{domain}/{dataset}Upload Data
    page.locator("text=POST/datasets/{domain}/{dataset}Upload Data").click()
    page.wait_for_url("http://service-image:8000/docs#/")

    print("Waiting for the table to be created")
    sleep(200)
    # ---------------------

    # Once the data is uploaded and table is created, we can query it

    # Go to http://service-image:8000/docs
    page.goto("http://service-image:8000/docs")

    # Click button:has-text("Authorize")
    page.locator('button:has-text("Authorize")').click()

    # Click input[type="text"]
    page.locator('input[type="text"]').click()

    # Click input[type="text"]
    page.locator('input[type="text"]').click()

    # Fill input[type="text"]
    page.locator('input[type="text"]').fill(cognito_client_id)

    # Click input[type="password"]
    page.locator('input[type="password"]').click()

    # Click input[type="password"]
    page.locator('input[type="password"]').click()

    # Fill input[type="password"]
    page.locator('input[type="password"]').fill(cognito_client_secret)

    # Click text=Authorize >> nth=1
    page.locator("text=Authorize").nth(1).click()

    # Click text=Close
    page.locator("text=Close").click()

    # Click text=POST/datasets/{domain}/{dataset}/queryQuery Dataset
    page.locator("text=POST/datasets/{domain}/{dataset}/queryQuery Dataset").click()
    page.wait_for_url(
        "http://service-image:8000/docs#/Datasets/query_dataset_datasets__domain___dataset__query_post"
    )

    # Click text=ParametersTry it out
    page.locator("text=ParametersTry it out").click()

    # Click button:has-text("Try it out")
    page.locator('button:has-text("Try it out")').click()

    # Click [placeholder="domain"]
    page.locator('[placeholder="domain"]').click()

    # Fill [placeholder="domain"]
    page.locator('[placeholder="domain"]').fill("playwright")

    # Press Tab
    page.locator('[placeholder="domain"]').press("Tab")

    # Fill [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').fill("playwright01")

    # Click text=Execute
    page.locator("text=Execute").click()

    # Click text=POST/datasets/{domain}/{dataset}/queryQuery Dataset
    page.locator("text=POST/datasets/{domain}/{dataset}/queryQuery Dataset").click()
    page.wait_for_url("http://service-image:8000/docs#/")

    # Click text=GET/statusStatus
    page.locator("text=GET/statusStatus").click()
    page.wait_for_url("http://service-image:8000/docs#/Status/status_status_get")

    # Click text=Try it out
    page.locator("text=Try it out").click()

    # Click text=Execute
    page.locator("text=Execute").click()

    # Click text=POST/datasetsList All Datasets
    page.locator("text=POST/datasetsList All Datasets").click()
    page.wait_for_url(
        "http://service-image:8000/docs#/Datasets/list_all_datasets_datasets_post"
    )

    # Click button:has-text("Try it out")
    page.locator('button:has-text("Try it out")').click()

    # Click #operations-Datasets-list_all_datasets_datasets_post >> text=Execute
    page.locator(
        "#operations-Datasets-list_all_datasets_datasets_post >> text=Execute"
    ).click()

    # Click text=POST/datasetsList All Datasets
    page.locator("text=POST/datasetsList All Datasets").click()
    page.wait_for_url("http://service-image:8000/docs#/")

    # Click text=GET/datasets/{domain}/{dataset}/infoGet Dataset Info
    page.locator("text=GET/datasets/{domain}/{dataset}/infoGet Dataset Info").click()
    page.wait_for_url(
        "http://service-image:8000/docs#/Datasets/get_dataset_info_datasets__domain___dataset__info_get"
    )

    # Click button:has-text("Try it out")
    page.locator('button:has-text("Try it out")').click()

    # Click [placeholder="domain"]
    page.locator('[placeholder="domain"]').click()

    # Fill [placeholder="domain"]
    page.locator('[placeholder="domain"]').fill("playwright")

    # Press Tab
    page.locator('[placeholder="domain"]').press("Tab")

    # Fill [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').fill("playwright01")

    # Click
    # #operations-Datasets-get_dataset_info_datasets__domain___dataset__info_get
    # >> text=Execute
    page.locator(
        "#operations-Datasets-get_dataset_info_datasets__domain___dataset__info_get >> text=Execute"
    ).click()

    # Click text=GET/datasets/{domain}/{dataset}/infoGet Dataset Info
    page.locator("text=GET/datasets/{domain}/{dataset}/infoGet Dataset Info").click()
    page.wait_for_url("http://service-image:8000/docs#/")

    # Click text=GET/datasets/{domain}/{dataset}/filesList Raw Files
    page.locator("text=GET/datasets/{domain}/{dataset}/filesList Raw Files").click()
    page.wait_for_url(
        "http://service-image:8000/docs#/Datasets/list_raw_files_datasets__domain___dataset__files_get"
    )

    # Click button:has-text("Try it out")
    page.locator('button:has-text("Try it out")').click()

    # Click [placeholder="domain"]
    page.locator('[placeholder="domain"]').click()

    # Fill [placeholder="domain"]
    page.locator('[placeholder="domain"]').fill("playwright")

    # Press Tab
    page.locator('[placeholder="domain"]').press("Tab")

    # Fill [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').fill("playwright01")

    # Click
    # #operations-Datasets-list_raw_files_datasets__domain___dataset__files_get
    # >> text=Execute
    page.locator(
        "#operations-Datasets-list_raw_files_datasets__domain___dataset__files_get >> text=Execute"
    ).click()

    # Click text=GET/datasets/{domain}/{dataset}/filesList Raw Files
    page.locator("text=GET/datasets/{domain}/{dataset}/filesList Raw Files").click()
    page.wait_for_url("http://service-image:8000/docs#/")

    # Click text=DELETE/datasets/{domain}/{dataset}/{filename}Delete Data File
    page.locator(
        "text=DELETE/datasets/{domain}/{dataset}/{filename}Delete Data File"
    ).click()
    page.wait_for_url(
        "http://service-image:8000/docs#/Datasets/delete_data_file_datasets__domain___dataset___filename__delete"
    )

    # Click button:has-text("Try it out")
    page.locator('button:has-text("Try it out")').click()

    # Click [placeholder="domain"]
    page.locator('[placeholder="domain"]').click()

    # Fill [placeholder="domain"]
    page.locator('[placeholder="domain"]').fill("playwright")

    # Press Tab
    page.locator('[placeholder="domain"]').press("Tab")

    # Fill [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').fill("playwright01")

    # Press Tab
    page.locator('[placeholder="dataset"]').press("Tab")

    # Click [placeholder="filename"]
    page.locator('[placeholder="filename"]').click()

    # Click [placeholder="filename"]
    page.locator('[placeholder="filename"]').click()

    # Get file name
    # session = boto3.Session()
    file_name = get_file_names(params)

    # Fill [placeholder="filename"]
    page.locator('[placeholder="filename"]').fill(file_name)

    # Click
    # #operations-Datasets-delete_data_file_datasets__domain___dataset___filename__delete
    # >> text=Execute
    page.locator(
        "#operations-Datasets-delete_data_file_datasets__domain___dataset___filename__delete >> text=Execute"
    ).click()

    # Click [placeholder="filename"]
    page.locator('[placeholder="filename"]').click()
    print("Playwright headless user journey completed")

    # ---------------------
    context.close()
    browser.close()

    # clean up
    print("Cleaning up...")
    cleanup_query_files(params)
    cleanup_data_files(params)
    cleanup_raw_files(params)
    athena_query(params)


with sync_playwright() as playwright:
    run(playwright)
