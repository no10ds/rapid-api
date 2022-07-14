from e2e_test_utils import get_secret
from playwright.sync_api import Playwright, sync_playwright
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "../../"))


def run(playwright: Playwright) -> None:
    browser = playwright.chromium.launch(headless=True, slow_mo=500)
    context = browser.new_context()

    # credentials = get_secret(
    #     secret_name="DEV_NO10DS_E2E_TEST_COGNITO_APP_CLIENT_ID_AND_SECRET"  # pragma: allowlist secret
    # )
    # cognito_client_id = credentials["CLIENT_ID"]
    # cognito_client_secret = credentials["CLIENT_SECRET"]  # pragma: allowlist secret
    credentials = get_secret(
        "DEV_NO10DS_E2E_TEST_COGNITO_APP_CLIENT_ID_AND_SECRET")  # pragma: allowlist secret
    cognito_client_id = credentials["CLIENT_ID"]
    cognito_client_secret = credentials["CLIENT_SECRET"]  # pragma: allowlist secret

    # Open new page
    page = context.new_page()

    # Go to http://localhost:8000/docs
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
    page.locator('[placeholder="sensitivity"]').fill("playwright")

    # Press Tab
    page.locator('[placeholder="sensitivity"]').press("Tab")

    # Fill [placeholder="domain"]
    page.locator('[placeholder="domain"]').fill("playwright")

    # Click [placeholder="sensitivity"]
    page.locator('[placeholder="sensitivity"]').click()

    # Fill [placeholder="sensitivity"]
    page.locator('[placeholder="sensitivity"]').fill("PUBLIC")

    # Press Tab
    page.locator('[placeholder="sensitivity"]').press("Tab")

    # Press Tab
    page.locator('[placeholder="domain"]').press("Tab")

    # Fill [placeholder="dataset"]
    page.locator('[placeholder="dataset"]').fill("playwright01")

    # Click input[type="file"]
    page.locator('input[type="file"]').click()

    # Upload test_journey_file.csv
    page.locator('input[type="file"]').set_input_files("test/e2e/test_journey_file.csv")

    # Click text=Execute
    page.locator("text=Execute").click()

    # ---------------------
    context.close()
    browser.close()


with sync_playwright() as playwright:
    run(playwright)
