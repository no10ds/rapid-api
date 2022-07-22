from typing import List
from unittest.mock import patch

import pytest

from api.application.services.authorisation.acceptable_permissions import AcceptablePermissions, \
    generate_acceptable_scopes
from api.common.config.auth import SensitivityLevel


@patch("api.application.services.authorisation.authorisation_service.s3_adapter")
@pytest.mark.parametrize(
    "domain, sensitivity, endpoint_scopes, acceptable_scopes",
    [
        (
                "domain",
                SensitivityLevel.PUBLIC,
                ["READ"],
                AcceptablePermissions(  # noqa: E126
                    required=set(),
                    optional={
                        "READ_ALL",
                        "READ_PUBLIC",
                        "READ_PRIVATE",
                    },
                ),
        ),
        (
                "domain",
                SensitivityLevel.PUBLIC,
                ["USER_ADMIN", "READ"],
                AcceptablePermissions(  # noqa: E126
                    required={"USER_ADMIN"},
                    optional={
                        "READ_ALL",
                        "READ_PUBLIC",
                        "READ_PRIVATE",
                    },
                ),
        ),
        (
                "domain",
                SensitivityLevel.PRIVATE,
                ["USER_ADMIN", "READ", "WRITE"],  # noqa: E126
                AcceptablePermissions(  # noqa: E126
                    required={"USER_ADMIN"},
                    optional={
                        "READ_ALL",
                        "WRITE_ALL",
                        "READ_PRIVATE",
                        "WRITE_PRIVATE",
                    },
                ),
        ),
        (
                None,
                None,
                ["USER_ADMIN"],
                AcceptablePermissions(required={"USER_ADMIN"}, optional=set()),  # noqa: E126
        ),
    ],
)
def test_generate_acceptable_scopes(
        mock_s3_adapter,
        domain: str,
        sensitivity: SensitivityLevel,
        endpoint_scopes: List[str],
        acceptable_scopes: AcceptablePermissions,
):
    mock_s3_adapter.get_dataset_sensitivity.return_value = sensitivity
    result = generate_acceptable_scopes(endpoint_scopes, sensitivity, domain)
    assert result == acceptable_scopes
