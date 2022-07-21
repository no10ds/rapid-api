from typing import List

import boto3

from api.common.config.aws import AWS_REGION
from api.common.custom_exceptions import UserError
from api.domain.client import ClientResponse
from api.domain.permission_item import PermissionItem

PERMISSIONS_TABLE_NAME = 'rapid_users_permissions'


class DynamoDBAdapter:
    def __init__(self,
                 dynamodb_client=boto3.client('dynamodb', region_name=AWS_REGION),
                 permissions_table_name=PERMISSIONS_TABLE_NAME):
        self.dynamodb_client = dynamodb_client
        self.permissions_table_name = permissions_table_name

    def create_client_item(self, client_info: ClientResponse):
        self.dynamodb_client.put_item(
            TableName=self.permissions_table_name,
            Item={
                "PK": {"S": "USR#Client"},
                "SK": {"S": f"USR#${client_info.client_id}"},
                "Id": {"S": f"${client_info.client_id}"},
                "Type": {"S": "Client"},
                "Permissions": {"SS": self.get_scope_ids(client_info.scopes)}
            }
        )

    def get_scope_ids(self, scopes: List[str]) -> List[str]:
        table_items = self.dynamodb_client.scan(
            TableName=self.permissions_table_name,
            ScanFilter={
                'PK': {
                    'AttributeValueList': [
                        {
                            'S': 'PER',
                        },
                    ],
                    'ComparisonOperator': 'BEGINS_WITH'
                }
            },
        )
        permissions_list = [self._generate_permission_item(item) for item in table_items['Items']]
        return self._validate_permissions(permissions_list, scopes)

    def get_permissions(self, subject_id: str):
        pass

    def _validate_permissions(self, permissions_list, scopes):
        valid_permission_ids = []
        for scope in scopes:
            scope_exists = False
            for permission in permissions_list:
                if scope == permission.permission:
                    scope_exists = True
                    valid_permission_ids.append(permission.id)
                    continue
            if not scope_exists:
                raise UserError("One or more of the provided scopes do not exist")
        return valid_permission_ids

    def _generate_permission_item(self, item: dict) -> PermissionItem:
        permission = PermissionItem(
            perm_id=item['Id'][list(item['Id'])[0]],
            sensitivity=item['Sensitivity'][list(item['Sensitivity'])[0]] if 'Sensitivity' in item else None,
            perm_type=item['Type'][list(item['Type'])[0]]
        )
        return permission
