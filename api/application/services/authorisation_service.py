from dataclasses import dataclass
from typing import Optional, List, Set

import jwt
from fastapi import Depends, HTTPException
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from fastapi.security import SecurityScopes
from fastapi.security.utils import get_authorization_scheme_param
from jwt import InvalidTokenError, PyJWKClient
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED

from api.adapter.dynamodb_adapter import DynamoDBAdapter
from api.adapter.s3_adapter import S3Adapter
from api.common.config.auth import (
    IDENTITY_PROVIDER_TOKEN_URL,
    COGNITO_JWKS_URL,
    COGNITO_RESOURCE_SERVER_ID,
    Action,
    SensitivityLevel,
    RAPID_ACCESS_TOKEN,
)
from api.common.custom_exceptions import (
    SchemaNotFoundError,
    AuthorisationError,
    UserCredentialsUnavailableError,
)
from api.common.logger import AppLogger


class OAuth2ClientCredentials(OAuth2):
    def __init__(
        self,
        token_url: str,
        scheme_name: str = None,
        allowed_scopes: dict = None,
        auto_error: bool = True,
    ):
        if not allowed_scopes:
            allowed_scopes = {}
        flows = OAuthFlowsModel(
            clientCredentials={"tokenUrl": token_url, "scopes": allowed_scopes}
        )
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, jwt_token = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            return None
        return jwt_token


class OAuth2UserCredentials:
    async def __call__(self, request: Request) -> Optional[str]:
        return request.cookies.get(RAPID_ACCESS_TOKEN, None)


oauth2_scheme = OAuth2ClientCredentials(token_url=IDENTITY_PROVIDER_TOKEN_URL)
oauth2_user_scheme = OAuth2UserCredentials()
jwks_client = PyJWKClient(COGNITO_JWKS_URL)
s3_adapter = S3Adapter()
db_adapter = DynamoDBAdapter()


def is_browser_request(request: Request) -> bool:
    accept_type = request.headers.get("Accept")
    return accept_type.startswith("text/html")


def user_logged_in(request: Request) -> bool:
    token = request.cookies.get(RAPID_ACCESS_TOKEN, None)
    return token is not None


def protect_endpoint(
    security_scopes: SecurityScopes,
    browser_request: str = Depends(is_browser_request),
    client_token: str = Depends(oauth2_scheme),
    user_token: str = Depends(oauth2_user_scheme),
):
    protect_dataset_endpoint(security_scopes, browser_request, client_token, user_token)


def protect_dataset_endpoint(
    security_scopes: SecurityScopes,
    browser_request: str = Depends(is_browser_request),
    client_token: str = Depends(oauth2_scheme),
    user_token: str = Depends(oauth2_user_scheme),
    domain: Optional[str] = None,
    dataset: Optional[str] = None,
):
    if user_token is not None:
        check_user_permissions(dataset, domain, security_scopes, user_token)
    else:
        if browser_request:
            raise UserCredentialsUnavailableError()

        else:
            if client_token:
                check_client_app_permissions(
                    client_token, dataset, domain, security_scopes
                )
            else:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED, detail="Not authenticated"
                )


def check_client_app_permissions(client_token, dataset, domain, security_scopes):
    try:
        permissions = retrieve_permissions(client_token)
        endpoint_permissions = security_scopes.scopes
        match_client_app_permissions(permissions, endpoint_permissions, domain, dataset)
    except SchemaNotFoundError:
        raise HTTPException(
            status_code=400,
            detail=f"Dataset [{dataset}] in domain [{domain}] does not exist",
        )


def check_user_permissions(dataset, domain, security_scopes, user_token):
    token_scopes = extract_user_groups(user_token)
    endpoint_scopes = security_scopes.scopes
    match_user_permissions(token_scopes, endpoint_scopes, domain, dataset)


def extract_user_groups(token: str) -> List[str]:
    try:
        payload = _get_validated_token_payload(token)
        return payload["cognito:groups"]
    except (InvalidTokenError, KeyError):
        AppLogger.warning(f"Invalid token format token={token}")
        raise AuthorisationError(
            "Not enough permissions or access token is missing/invalid"
        )


def retrieve_permissions(token: str) -> List[str]:
    try:
        payload = _get_validated_token_payload(token)
        retrieved_permissions = db_adapter.get_permissions(payload["sub"])
        if not retrieved_permissions:
            scopes = payload["scope"].split()
            retrieved_permissions = [scope.split(COGNITO_RESOURCE_SERVER_ID + "/", 1)[1] for scope in scopes]
        return retrieved_permissions
    except (InvalidTokenError, KeyError):
        AppLogger.warning(f"Invalid token format token={token}")
        raise AuthorisationError(
            "Not enough permissions or access token is missing/invalid"
        )


def match_client_app_permissions(
    token_scopes: list, endpoint_scopes: list, domain: str = None, dataset: str = None
):
    acceptable_scopes = generate_acceptable_scopes(endpoint_scopes, domain, dataset)
    if not acceptable_scopes.satisfied_by(token_scopes):
        raise AuthorisationError("Not enough permissions to access endpoint")


def match_user_permissions(
    token_scopes: list,
    endpoint_scopes: list,
    domain: Optional[str] = None,
    dataset: Optional[str] = None,
):
    if domain and dataset:
        allowed_permissions = [
            f"{permission}/{domain}/{dataset}" for permission in endpoint_scopes
        ]
        if not any(
                [
                    allowed_permission in token_scopes
                    for allowed_permission in allowed_permissions
                ]
        ):
            raise AuthorisationError("Not enough permissions to access endpoint")
    elif (not domain and dataset) or (domain and not dataset):
        raise AuthorisationError("Not enough permissions to access endpoint")


@dataclass
class AcceptedScopes:
    required: Set[str]
    optional: Set[str]

    def satisfied_by(self, token_scopes: List[str]) -> bool:
        all_required = all(
            [required_scope in token_scopes for required_scope in self.required]
        )
        any_optional = (
            any([any_scope in token_scopes for any_scope in self.optional])
            if self.optional
            else True
        )

        return all_required and any_optional


def generate_acceptable_scopes(
        endpoint_actions: List[str], domain: str = None, dataset: str = None
) -> AcceptedScopes:
    endpoint_actions = [Action.from_string(action) for action in endpoint_actions]

    required_scopes = set()
    optional_scopes = set()

    for action in endpoint_actions:

        if action in Action.standalone_actions():
            required_scopes.add(action.value)
            continue

        acceptable_sensitivities = _get_acceptable_sensitivity_values(dataset, domain)

        optional_scopes.add(f"{action.value}_ALL")
        for acceptable_sensitivity in acceptable_sensitivities:
            optional_scopes.add(f"{action.value}_{acceptable_sensitivity}")

    return AcceptedScopes(required_scopes, optional_scopes)


def _get_acceptable_sensitivity_values(dataset: str, domain: str) -> List[str]:
    sensitivity = s3_adapter.get_dataset_sensitivity(domain, dataset)
    if sensitivity == SensitivityLevel.PROTECTED:
        return [f"{SensitivityLevel.PROTECTED.value}_{domain.upper()}"]
    else:
        implied_sensitivity_map = {
            # The levels in the values imply the levels in the key
            SensitivityLevel.PUBLIC: [
                SensitivityLevel.PRIVATE,
                SensitivityLevel.PUBLIC,
            ],
            SensitivityLevel.PRIVATE: [
                SensitivityLevel.PRIVATE,
            ],
        }
        acceptable_sensitivities = (
            implied_sensitivity_map.get(sensitivity, [sensitivity])
            if sensitivity
            else []
        )
        return [sensitivity.value for sensitivity in acceptable_sensitivities]


def _get_validated_token_payload(token):
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(token, signing_key.key, algorithms=["RS256"])
