from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator


class RegisterIn(BaseModel):
    email: EmailStr
    display_name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=128)
    accept_terms: bool

    @field_validator("display_name")
    @classmethod
    def trim_name(cls, value):
        value = value.strip()
        if not value:
            raise ValueError("Display name is required")
        return value


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    ecosystem: str = Field(default="mixed", max_length=40)

    @field_validator("name")
    @classmethod
    def trim_name(cls, value):
        value = value.strip()
        if not value:
            raise ValueError("Project name is required")
        return value

    @field_validator("ecosystem")
    @classmethod
    def valid_ecosystem(cls, value):
        if value not in {"mixed", "python", "javascript", "java", "go", "rust"}:
            raise ValueError("Unsupported project ecosystem")
        return value


class ProjectPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    ecosystem: str | None = Field(default=None, max_length=40)
    archived: bool | None = None

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("Project name is required")
        return value

    @field_validator("ecosystem")
    @classmethod
    def valid_ecosystem(cls, value):
        if value is not None and value not in {"mixed", "python", "javascript", "java", "go", "rust"}:
            raise ValueError("Unsupported project ecosystem")
        return value


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordReset(BaseModel):
    token: str = Field(min_length=30, max_length=200)
    new_password: str = Field(min_length=12, max_length=128)


class AccountDelete(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    confirm: bool


class RoleUpdate(BaseModel):
    role: str


class StatusUpdate(BaseModel):
    is_active: bool


class AuditorGrant(BaseModel):
    email: EmailStr


class SBOMSource(BaseModel):
    kind: Literal["imported", "generated"]
    id: UUID


class SBOMCompareIn(BaseModel):
    left: SBOMSource
    right: SBOMSource


class SecurityPolicyIn(BaseModel):
    max_allowed_priority: Literal["Low", "Medium", "High", "Critical"] = "High"
    fail_on_kev: bool = True
    partial_behavior: Literal["warning", "fail"] = "warning"
    unavailable_behavior: Literal["warning", "fail"] = "warning"
    fail_on_unknown_license: bool = False
    allowed_licenses: list[str] = Field(default_factory=list, max_length=100)
    restricted_licenses: list[str] = Field(default_factory=list, max_length=100)

    @field_validator("allowed_licenses", "restricted_licenses")
    @classmethod
    def validate_license_ids(cls, values):
        output = []
        for value in values:
            clean = value.strip()
            if not clean or len(clean) > 60 or any(ord(char) < 32 for char in clean):
                raise ValueError("License identifiers must be short printable strings")
            if clean not in output:
                output.append(clean)
        return output

    @model_validator(mode="after")
    def disjoint_license_lists(self):
        if set(self.allowed_licenses) & set(self.restricted_licenses):
            raise ValueError("A license cannot be both allowed and restricted")
        return self


class MonitoringScheduleIn(BaseModel):
    interval_hours: int = Field(ge=6, le=720)
    active: bool = True


class NotificationPreferenceIn(BaseModel):
    email_enabled: bool


class ExplanationOut(BaseModel):
    explanation: str
    potential_impact: str
    priority_reasoning: str
    remediation: str
    uncertainty: str
    references: list[str]
    generated_by: str


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
