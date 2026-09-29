"""Edge definitions for InfraGraph."""
from enum import Enum
from typing import Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class EdgeType(str, Enum):
    OWNS = "OWNS"
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    ALIAS_OF = "ALIAS_OF"
    HOSTED_ON = "HOSTED_ON"
    BELONGS_TO_ASN = "BELONGS_TO_ASN"
    IN_CIDR = "IN_CIDR"
    DANGLING_TARGET = "DANGLING_TARGET"
    EXPOSES_SERVICE = "EXPOSES_SERVICE"


class BaseEdge(BaseModel):
    source_id: str
    target_id: str
    type: EdgeType
    label: str = ""
    confidence: float = 1.0
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def key(self) -> str:
        return f"{self.source_id}->{self.type.value}->{self.target_id}"
