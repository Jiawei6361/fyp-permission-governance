"""Pydantic models for the Microsoft Graph v1.0 driveItem `permission` resource
(plus the Power Automate flow properties we rely on)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Identity(_Strict):
    id: str
    displayName: str
    email: str | None = None


class SharePointIdentity(Identity):
    loginName: str | None = None


class SharePointIdentitySet(_Strict):
    user: Identity | None = None
    group: Identity | None = None
    application: Identity | None = None
    siteUser: SharePointIdentity | None = None
    siteGroup: SharePointIdentity | None = None

    @model_validator(mode="after")
    def _one_identity(self):
        if not any(v is not None for v in self.__dict__.values()):
            raise ValueError("identity set is empty")
        return self


class SharingLink(_Strict):
    type: Literal["view", "edit", "embed"]
    scope: Literal["anonymous", "organization", "users"]
    webUrl: str
    preventsDownload: bool = False


class ItemReference(_Strict):
    driveId: str
    id: str
    path: str


class Permission(_Strict):
    id: str
    roles: list[Literal["read", "write", "owner"]]
    grantedToV2: SharePointIdentitySet | None = None
    grantedToIdentitiesV2: list[SharePointIdentitySet] | None = None
    link: SharingLink | None = None
    inheritedFrom: ItemReference | None = None
    hasPassword: bool | None = None

    @model_validator(mode="after")
    def _has_grantee(self):
        if not self.roles:
            raise ValueError("roles must not be empty")
        if self.link is None and self.grantedToV2 is None and not self.grantedToIdentitiesV2:
            raise ValueError("permission needs a link or a grantee")
        return self


class FlowConnectionReference(_Strict):
    connectionName: str
    id: str
    displayName: str
    tier: str


class FlowProperties(BaseModel):
    model_config = ConfigDict(extra="allow")
    displayName: str
    state: Literal["Started", "Stopped", "Suspended"]
    connectionReferences: dict[str, FlowConnectionReference]
    definition: dict


class FlowResource(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str
    id: str
    type: Literal["Microsoft.ProcessSimple/environments/flows"]
    properties: FlowProperties
