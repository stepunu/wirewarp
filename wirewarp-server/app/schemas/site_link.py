import ipaddress
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator


class SiteLinkAccessRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    direction: Literal["a_to_b", "b_to_a"]
    destination_cidrs: list[str] = Field(min_length=1, max_length=32)
    protocol: Literal["tcp", "udp", "icmp", "any"]
    destination_ports: list[int] = Field(default_factory=list, max_length=64)

    @field_validator("destination_cidrs")
    @classmethod
    def ipv4_networks(cls, value):
        return canonical_subnets(value)

    @model_validator(mode="after")
    def valid_ports(self):
        if any(port < 1 or port > 65535 for port in self.destination_ports):
            raise ValueError("Destination ports must be between 1 and 65535")
        if self.protocol in {"icmp", "any"} and self.destination_ports:
            raise ValueError("Only TCP and UDP rules accept destination ports")
        self.destination_ports = sorted(set(self.destination_ports))
        return self


def canonical_subnets(value: list[str]) -> list[str]:
    networks = [ipaddress.IPv4Network(item, strict=True) for item in value]
    if any(network.prefixlen == 0 or network.is_multicast or network.is_loopback or network.is_link_local for network in networks):
        raise ValueError("Site subnets must be unicast IPv4 networks")
    if any(a.overlaps(b) for i, a in enumerate(networks) for b in networks[i + 1:]):
        raise ValueError("Subnets must not overlap")
    return sorted(str(network) for network in networks)


class SiteLinkCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    site_a_gateway_id: uuid.UUID
    site_b_gateway_id: uuid.UUID
    site_a_attachment_id: uuid.UUID
    site_b_attachment_id: uuid.UUID
    hub_agent_id: uuid.UUID
    site_a_subnets: list[str] = Field(min_length=1, max_length=16)
    site_b_subnets: list[str] = Field(min_length=1, max_length=16)
    direction: Literal["a_to_b", "b_to_a", "bidirectional"] = "bidirectional"
    snat_at_a: bool = True
    snat_at_b: bool = True
    access_rules: list[SiteLinkAccessRule] = Field(default_factory=list, max_length=64)
    enabled: bool = True

    @field_validator("site_a_subnets", "site_b_subnets")
    @classmethod
    def ipv4_networks(cls, value):
        return canonical_subnets(value)


class SiteLinkUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=120)
    direction: Literal["a_to_b", "b_to_a", "bidirectional"] | None = None
    snat_at_a: bool | None = None
    snat_at_b: bool | None = None
    access_rules: list[SiteLinkAccessRule] | None = Field(default=None, max_length=64)
    enabled: bool | None = None

    @model_validator(mode="after")
    def no_null_updates(self):
        if any(getattr(self, key) is None for key in self.model_fields_set):
            raise ValueError("Site link fields cannot be null")
        return self


class SiteLinkTest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    direction: Literal["a_to_b", "b_to_a"]
    destination_ip: str
    destination_port: int = Field(ge=1, le=65535)

    @field_validator("destination_ip")
    @classmethod
    def ipv4_address(cls, value):
        return str(ipaddress.IPv4Address(value))


class SiteLinkExpectedState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: uuid.UUID
    revision: int = Field(ge=1)
    desired_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class SiteLinkTeardown(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm_restore_normal_forwarding: Literal[True]
    expected_states: list[SiteLinkExpectedState] = Field(min_length=1)

    @field_validator("confirm_restore_normal_forwarding", mode="before")
    @classmethod
    def explicit_confirmation(cls, value):
        if value is not True:
            raise ValueError("Confirm restoration of normal forwarding with true")
        return value
