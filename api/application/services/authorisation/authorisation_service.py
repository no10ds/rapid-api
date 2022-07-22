from typing import Optional, List

from fastapi import Depends, HTTPException
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2
from fastapi.security import SecurityScopes
from fastapi.security.utils import get_authorization_scheme_param
from jwt import InvalidTokenError, PyJWKClient
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_403_FORBIDDEN

from api.adapter.s3_adapter import S3Adapter
from api.application.services.authorisation.acceptable_permissions import generate_acceptable_scopes
from api.application.services.authorisation.token_utils import parse_token, _get_validated_token_payload
from api.common.config.auth import (
    IDENTITY_PROVIDER_TOKEN_URL,
    COGNITO_JWKS_URL,
    COGNITO_RESOURCE_SERVER_ID,
    RAPID_ACCESS_TOKEN,
)
from api.common.custom_exceptions import (
    SchemaNotFoundError,
    AuthorisationError,
    UserCredentialsUnavailableError,
)
from api.common.logger import AppLogger
from api.domain.token import Token


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
s3_adapter = S3Adapter()


def is_browser_request(request: Request) -> bool:
    accept_type = request.headers.get("Accept")
    return accept_type.startswith("text/html")


def user_logged_in(request: Request) -> bool:
    token = request.cookies.get(RAPID_ACCESS_TOKEN, None)
    return token is not None


def protect_endpoint(
    security_scopes: SecurityScopes,
    browser_request: bool = Depends(is_browser_request),
    client_token: str = Depends(oauth2_scheme),
    user_token: str = Depends(oauth2_user_scheme),
):
    protect_dataset_endpoint(security_scopes, browser_request, client_token, user_token)


def protect_dataset_endpoint(
    security_scopes: SecurityScopes,
    browser_request: bool = Depends(is_browser_request),
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


def secure_dataset_endpoint(
    security_scopes: SecurityScopes,
    browser_request: bool = Depends(is_browser_request),
    client_token: Optional[str] = Depends(oauth2_scheme),
    user_token: Optional[str] = Depends(oauth2_user_scheme),
    domain: Optional[str] = None,
    dataset: Optional[str] = None,
):
    check_credentials_availability(browser_request, client_token, user_token)

    try:
        token = user_token if user_token else client_token
        token = parse_token(token)
        check_permissions(token, security_scopes.scopes, domain, dataset)
    except InvalidTokenError as error:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail=str(error))


def check_credentials_availability(
    browser_request: bool, client_token: str, user_token: str
) -> None:
    if not have_credentials(browser_request, client_token, user_token):
        if browser_request:
            raise UserCredentialsUnavailableError()
        else:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="You are not authorised to perform this action",
            )


def have_credentials(browser_request: bool, client_token: str, user_token: str) -> bool:
    return have_user_credentials(
        browser_request, user_token
    ) or have_client_credentials(client_token)


def check_permissions(
    token: Token, endpoint_scopes: List[str], domain: str, dataset: str
):
    raise NotImplementedError()


def have_user_credentials(browser_request: bool, user_token: Optional[str]) -> bool:
    return bool(browser_request and user_token)


def have_client_credentials(client_token: Optional[str]) -> bool:
    return bool(client_token)


def check_client_app_permissions(client_token, dataset, domain, security_scopes):
    try:
        token_scopes = extract_client_app_scopes(client_token)
        endpoint_scopes = security_scopes.scopes
        match_client_app_permissions(token_scopes, endpoint_scopes, domain, dataset)
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


def extract_client_app_scopes(token: str) -> List[str]:
    try:
        payload = _get_validated_token_payload(token)
        scopes = payload["scope"].split()
        return [scope.split(COGNITO_RESOURCE_SERVER_ID + "/", 1)[1] for scope in scopes]
    except (InvalidTokenError, KeyError):
        AppLogger.warning(f"Invalid token format token={token}")
        raise AuthorisationError(
            "Not enough permissions or access token is missing/invalid"
        )


def match_client_app_permissions(
    token_scopes: list, endpoint_scopes: list, domain: str = None, dataset: str = None
):
    sensitivity = s3_adapter.get_dataset_sensitivity(domain, dataset)
    acceptable_scopes = generate_acceptable_scopes(endpoint_scopes, sensitivity, domain)
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


