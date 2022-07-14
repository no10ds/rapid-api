from playwright.sync_api import Playwright, sync_playwright


def run(playwright: Playwright) -> None:
    browser = playwright.chromium.launch(headless=True, slow_mo=50)
    context = browser.new_context()

    # Open new page
    page = context.new_page()

    # Go to http://service-image:8000/docs
    page.goto("http://service-image:8000/docs")
    print(page.title())

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

    # Click [placeholder="domain"]
    page.locator('[placeholder="domain"]').click()

    # Fill [placeholder="domain"]
    page.locator('[placeholder="domain"]').fill("test")

    # Click [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').click()

    # Fill [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').fill("journey")

    # Press ArrowLeft
    page.locator('[placeholder="dataset"]').press("ArrowLeft")

    # Press ArrowLeft
    page.locator('[placeholder="dataset"]').press("ArrowLeft")

    # Press ArrowLeft
    page.locator('[placeholder="dataset"]').press("ArrowLeft")

    # Press ArrowLeft
    page.locator('[placeholder="dataset"]').press("ArrowLeft")

    # Press ArrowLeft
    page.locator('[placeholder="dataset"]').press("ArrowLeft")

    # Press ArrowLeft
    page.locator('[placeholder="dataset"]').press("ArrowLeft")

    # Press ArrowLeft
    page.locator('[placeholder="dataset"]').press("ArrowLeft")

    # Fill [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').fill("e2e_journey")

    # Click input[type="file"]
    page.locator('input[type="file"]').click()

    # Upload test_journey_file.csv
    page.locator('input[type="file"]').set_input_files(
        "/app/test/e2e/test_journey_file.csv"
    )

    # Click text=Execute
    page.locator("text=Execute").click()

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

    # Click text=POST/schema/{sensitivity}/{domain}/{dataset}/generateGenerate Schema
    page.locator(
        "text=POST/schema/{sensitivity}/{domain}/{dataset}/generateGenerate Schema"
    ).click()
    page.wait_for_url(
        "http://service-image:8000/docs#/Schema/generate_schema_schema__sensitivity___domain___dataset__generate_post"
    )

    # # Click .highlight-code > .copy-to-clipboard > button
    # page.locator(".highlight-code > .copy-to-clipboard > button").click()

    # Click text=POST/schema/{sensitivity}/{domain}/{dataset}/generateGenerate Schema
    page.locator(
        "text=POST/schema/{sensitivity}/{domain}/{dataset}/generateGenerate Schema"
    ).click()
    page.wait_for_url("http://service-image:8000/docs#/")

    # Click textarea
    page.locator("textarea").click()

    # Press a with modifiers
    page.locator("textarea").fill("")
    page.wait_for_timeout(12000)

    # Fill textarea
    page.locator("textarea").fill(
        '{\n  "metadata": {\n    "domain": "test",\n    "dataset": "e2e_journey",\n    "sensitivity": "PUBLIC",\n    "key_value_tags": {},\n    "key_only_tags": [],\n    "owners": [\n      {\n        "name": "test",\n        "email": "test@email.com"\n      }\n    ],\n    "update_behaviour": "APPEND"\n  },\n  "columns": [\n    {\n      "name": "year",\n      "partition_index": null,\n      "data_type": "Int64",\n      "allow_null": true,\n      "format": null\n    },\n    {\n      "name": "month",\n      "partition_index": null,\n      "data_type": "Int64",\n      "allow_null": true,\n      "format": null\n    },\n    {\n      "name": "destination",\n      "partition_index": null,\n      "data_type": "object",\n      "allow_null": true,\n      "format": null\n    },\n    {\n      "name": "arrival",\n      "partition_index": null,\n      "data_type": "object",\n      "allow_null": true,\n      "format": null\n    },\n    {\n      "name": "type",\n      "partition_index": null,\n      "data_type": "object",\n      "allow_null": true,\n      "format": null\n    },\n    {\n      "name": "status",\n      "partition_index": null,\n      "data_type": "object",\n      "allow_null": true,\n      "format": null\n    }\n  ]\n}'
    )
    page.wait_for_timeout(8000)
    # ---------------------
    context.close()
    browser.close()


with sync_playwright() as playwright:
    run(playwright)
