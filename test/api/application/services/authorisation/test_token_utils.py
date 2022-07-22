from unittest.mock import patch

import pytest

from api.application.services.authorisation.token_utils import parse_token


class TestParseToken:
    @patch("api.application.services.authorisation.token_utils.Token")
    @patch(
        "api.application.services.authorisation.token_utils._get_validated_token_payload"
    )
    def test_parses_user_token_with_groups(self, mock_token_payload, mock_token):
        token = "user-token"

        payload = {
            "sub": "the-user-id",
            "cognito:groups": ["group1", "group2"],
            "scope": "scope1 scope2 scope3",
        }

        mock_token_payload.return_value = payload

        parse_token(token)

        mock_token_payload.assert_called_once_with("user-token")
        mock_token.assert_called_once_with(payload)

    @patch("api.domain.token.COGNITO_RESOURCE_SERVER_ID", "https://example.com")
    @patch("api.application.services.authorisation.token_utils.Token")
    @patch(
        "api.application.services.authorisation.token_utils._get_validated_token_payload"
    )
    def test_parses_client_token_with_scopes(self, mock_token_payload, mock_token):
        token = "client-token"

        payload = {
            "sub": "the-client-id",
            "scope": "https://example.com/scope1 https://example.com/scope2",
        }

        mock_token_payload.return_value = payload

        parse_token(token)

        mock_token_payload.assert_called_once_with("client-token")
        mock_token.assert_called_once_with(payload)

    @patch("api.application.services.authorisation.token_utils.Token")
    @patch(
        "api.application.services.authorisation.token_utils._get_validated_token_payload"
    )
    def test_parses_user_token_with_no_permissions(
        self, mock_token_payload, mock_token
    ):
        token = "user-token"

        payload = {
            "sub": "the-user-id",
            "scope": "scope1 scope2 scope3",
        }

        mock_token_payload.return_value = payload

        parse_token(token)

        mock_token_payload.assert_called_once_with("user-token")
        mock_token.assert_called_once_with(payload)

    @patch("api.application.services.authorisation.token_utils.Token")
    @patch(
        "api.application.services.authorisation.token_utils._get_validated_token_payload"
    )
    def test_passes_errors_through(self, _mock_token_payload, mock_token):
        mock_token.side_effect = ValueError("Error detail")

        with pytest.raises(ValueError, match="Error detail"):
            parse_token("user-token")
