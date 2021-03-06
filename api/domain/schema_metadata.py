from dataclasses import dataclass
from typing import Dict, List, Optional

from pydantic import BaseModel, EmailStr

from api.common.config.auth import SensitivityLevel
from api.common.config.aws import SCHEMAS_LOCATION
from api.common.custom_exceptions import SchemaNotFoundError
from api.common.data_parsers import parse_categorisation
from api.common.utilities import BaseEnum


class Owner(BaseModel):
    name: str
    email: EmailStr


class UpdateBehaviour(BaseEnum):
    APPEND = "APPEND"
    OVERWRITE = "OVERWRITE"


class SchemaMetadata(BaseModel):
    domain: str
    dataset: str
    sensitivity: str
    key_value_tags: Dict[str, str] = dict()
    key_only_tags: List[str] = list()
    owners: Optional[List[Owner]] = None
    update_behaviour: str = UpdateBehaviour.APPEND.value

    def get_domain(self) -> str:
        return self.domain

    def get_dataset(self) -> str:
        return self.dataset

    def get_sensitivity(self) -> str:
        return self.sensitivity

    def schema_path(self) -> str:
        return f"{SCHEMAS_LOCATION}/{self.sensitivity}/{self.schema_name()}"

    def schema_name(self) -> str:
        return f"{self.domain}-{self.dataset}.json"

    @classmethod
    def from_path(cls, path: str):
        sensitivity = parse_categorisation(path, SensitivityLevel.values(), "PUBLIC")
        domain, dataset = path.split("/")[-1].replace(".json", "").split("-")
        return cls(domain=domain, dataset=dataset, sensitivity=sensitivity)

    def get_custom_tags(self) -> Dict[str, str]:
        return {**self.key_value_tags, **dict.fromkeys(self.key_only_tags, "")}

    def get_tags(self) -> Dict[str, str]:
        return {**self.get_custom_tags(), "sensitivity": self.get_sensitivity()}

    def get_owners(self) -> Optional[List[Owner]]:
        return self.owners

    def get_update_behaviour(self) -> str:
        return self.update_behaviour

    def remove_duplicates(self):
        updated_key_only_list = []

        if len(self.key_only_tags) != 0 and self.key_value_tags:
            for key in self.key_only_tags:
                if key not in self.key_value_tags.keys():
                    updated_key_only_list.append(key)

        self.key_only_tags = updated_key_only_list


@dataclass
class SchemaMetadatas:
    metadatas: List[SchemaMetadata]

    def find(self, domain: str, dataset: str) -> SchemaMetadata:
        try:
            return list(
                filter(
                    lambda data: data.domain == domain and data.dataset == dataset,
                    self.metadatas,
                )
            )[0]
        except IndexError:
            raise SchemaNotFoundError(
                f"Schema not found for domain={domain} and dataset={dataset}"
            )

    @classmethod
    def empty(cls):
        return cls([])
