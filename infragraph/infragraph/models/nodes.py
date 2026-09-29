"""Node definitions for InfraGraph."""
from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class NodeType(str, Enum):
    ORGANIZATION = "ORGANIZATION"
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP = "IP"
    ASN = "ASN"
    CIDR = "CIDR"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    DNS_RECORD = "DNS_RECORD"
    SERVICE_PORT = "SERVICE_PORT"


class RiskLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class BaseNode(BaseModel):
    id: str
    type: NodeType
    label: str
    risk_level: RiskLevel = RiskLevel.INFO
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def update_seen(self):
        self.last_seen = datetime.now(timezone.utc).isoformat()
