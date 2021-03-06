from unittest.mock import patch, Mock

from api.application.services.protected_domain_service import ProtectedDomainService
from test.api.controller.controller_test_utils import BaseClientTest


class TestProtectedDomains(BaseClientTest):
    @patch.object(ProtectedDomainService, "create_scopes")
    def test_scopes_creation(self, mock_create_scopes: Mock):

        response = self.client.post(
            "/protected_domains/new",
            headers={"Authorization": "Bearer test-token"},
        )

        mock_create_scopes.assert_called_once_with("new")

        assert response.status_code == 201
        assert response.json() == "Successfully created protected domain for new"

    @patch.object(ProtectedDomainService, "list_domains")
    def test_list_domains(self, mock_list_domains: Mock):

        mock_list_domains.return_value = ["test"]

        response = self.client.get(
            "/protected_domains",
            headers={"Authorization": "Bearer test-token"},
        )

        mock_list_domains.assert_called_once()

        assert response.status_code == 200
        assert response.json() == ["test"]
