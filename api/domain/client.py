import re
from typing import Optional, List

from pydantic import BaseModel

from api.common.config.auth import DEFAULT_SCOPE
from api.common.custom_exceptions import UserError


class ClientRequest(BaseModel):
    client_name: str
    scopes: Optional[List[str]] = DEFAULT_SCOPE

    def get_validated_client_name(self):
        """
        We restrict further beyond Cognito limits:
        https://docs.aws.amazon.com/cognito/latest/developerguide/limits.html
        """
        if self.client_name is not None and re.fullmatch("[a-zA-Z][a-zA-Z0-9@._-]{2,127}", self.client_name):
            return self.client_name
        raise UserError("Invalid client name provided")

    def get_scopes(self) -> List[str]:
        return self.scopes


class ClientResponse(BaseModel):
    client_name: str
    scopes: List[str]
    client_id: str
    client_secret: str
