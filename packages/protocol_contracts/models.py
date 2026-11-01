"""Receipt and manifest contracts for the offline verifier.

The canonical profile rejects IEEE 754 floats, normalizes keys to NFC, and
orders object keys by UTF-16 code units (RFC 8785). Money is an integer count
of cents.
"""

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

DOMAIN_REQ_V1: bytes = b"SENTINEL-REQ-V1\x00"
DOMAIN_APPROVAL_V1: bytes = b"SENTINEL-APPR-V1\x00"
DOMAIN_RECEIPT_V1: bytes = b"SENTINEL-RCPT-V1\x00"
DOMAIN_MANIFEST_V1: bytes = b"SENTINEL-MFST-V1\x00"


class PrincipalType(StrEnum):
    WORKLOAD = "WORKLOAD"
    HUMAN_APPROVER = "HUMAN_APPROVER"
    CUSTODY_LEDGER = "CUSTODY_LEDGER"


class OperationClass(StrEnum):
    READ_ONLY = "READ_ONLY"
    STATE_MUTATION = "STATE_MUTATION"
    ADMINISTRATIVE = "ADMINISTRATIVE"


class PolicyDecisionType(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ExecutionState(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    DENIED = "DENIED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    RECONCILING = "RECONCILING"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    SEALED = "SEALED"


class KeyLifecycleStatus(StrEnum):
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    COMPROMISED = "COMPROMISED"


def format_utc_microseconds(dt: datetime) -> str:
    """Formats a timezone-aware UTC datetime into strict YYYY-MM-DDTHH:MM:SS.ffffffZ."""
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("Datetime must be timezone-aware UTC.")
    utc_dt = dt.astimezone(UTC)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _utf16_code_units_sort_key(key_str: str) -> bytes:
    """RFC 8785 Section 3.2.3 property sorting key based on UTF-16 code units."""
    return key_str.encode("utf-16-be")


def _normalize_jcs_value(val: Any) -> Any:
    """Reject floats, normalize NFC, and order object keys by UTF-16 code units."""
    if isinstance(val, float):
        raise ValueError(  # noqa: TRY004
            "IEEE 754 floats are prohibited in canonical contracts; use int or str."
        )
    if isinstance(val, bool) or val is None or isinstance(val, int):
        return val
    if isinstance(val, str):
        return unicodedata.normalize("NFC", val)
    if isinstance(val, UUID):
        return str(val).lower()
    if isinstance(val, datetime):
        return format_utc_microseconds(val)
    if isinstance(val, StrEnum):
        return unicodedata.normalize("NFC", val.value)
    if isinstance(val, (list, tuple)):
        return [_normalize_jcs_value(item) for item in val]
    if isinstance(val, frozenset):
        normalized_items = [_normalize_jcs_value(item) for item in val]
        return sorted(normalized_items, key=lambda item: _utf16_code_units_sort_key(str(item)))
    if isinstance(val, dict):
        temp_dict: dict[str, Any] = {}
        for key, value in val.items():
            if not isinstance(key, str):
                raise ValueError(  # noqa: TRY004
                    "All JSON object keys in canonical contracts must be strings."
                )
            norm_key = unicodedata.normalize("NFC", key)
            if norm_key in temp_dict:
                raise ValueError(f"DUPLICATE_CANONICAL_KEY_AFTER_NFC: {norm_key!r}")
            temp_dict[norm_key] = _normalize_jcs_value(value)
        sorted_keys = sorted(temp_dict.keys(), key=_utf16_code_units_sort_key)
        return {key: temp_dict[key] for key in sorted_keys}
    raise TypeError(f"Unsupported type for canonicalization: {type(val).__name__}")


def canonicalize_jcs_bytes(data: Any) -> bytes:
    """Produces deterministic UTF-8 bytes with UTF-16 key order per RFC 8785."""
    normalized = _normalize_jcs_value(data)
    canonical_str = json.dumps(
        normalized,
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonical_str.encode("utf-8")


class ImmutableContractModel(BaseModel):
    """Base model enforcing strict typing, immutability, and extra field rejection."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class WorkloadIdentity(ImmutableContractModel):
    tenant_id: UUID
    principal_type: PrincipalType = Field(default=PrincipalType.WORKLOAD)
    subject: str = Field(..., min_length=2, max_length=256)
    issuer: str = Field(..., min_length=3, max_length=256)
    audience: str = Field(..., min_length=3, max_length=128)
    scopes: frozenset[str]


class ToolCallRequest(ImmutableContractModel):
    schema_version: str = Field(default="sentinel.req.v1")
    request_id: UUID
    correlation_id: UUID
    idempotency_key: str = Field(..., min_length=8, max_length=128)
    identity: WorkloadIdentity
    tool_name: str = Field(..., min_length=1, max_length=128)
    operation_class: OperationClass
    resource_uri: str = Field(..., min_length=1, max_length=512)
    arguments: dict[str, Any]
    requested_at_utc: datetime

    @field_validator("arguments")
    @classmethod
    def validate_no_floats_in_arguments(cls, v: dict[str, Any]) -> dict[str, Any]:
        _normalize_jcs_value(v)
        return v

    @property
    def canonical_args_hash(self) -> str:
        return hashlib.sha256(canonicalize_jcs_bytes(self.arguments)).hexdigest()

    def signing_bytes(self) -> bytes:
        payload = {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "tenant_id": self.identity.tenant_id,
            "idempotency_key": self.idempotency_key,
            "workload_subject": self.identity.subject,
            "tool_name": self.tool_name,
            "operation_class": self.operation_class.value,
            "resource_uri": self.resource_uri,
            "canonical_args_hash": self.canonical_args_hash,
            "requested_at_utc": self.requested_at_utc,
        }
        return DOMAIN_REQ_V1 + canonicalize_jcs_bytes(payload)

    @property
    def request_hash(self) -> str:
        return hashlib.sha256(self.signing_bytes()).hexdigest()


class PolicyDecision(ImmutableContractModel):
    decision: PolicyDecisionType
    reason_code: str = Field(..., min_length=2, max_length=128)
    policy_bundle_hash: str = Field(..., min_length=64, max_length=64)


class ApprovalRecord(ImmutableContractModel):
    schema_version: str = Field(default="sentinel.approval.v1")
    approval_id: UUID
    tenant_id: UUID
    request_id: UUID
    request_hash: str = Field(..., min_length=64, max_length=64)
    approver_subject: str = Field(..., min_length=3, max_length=256)
    approver_principal_type: PrincipalType = Field(default=PrincipalType.HUMAN_APPROVER)
    approver_key_id: str = Field(..., min_length=3, max_length=128)
    justification: str = Field(..., min_length=5, max_length=512)
    approved_at_utc: datetime
    expires_at_utc: datetime
    ed25519_signature_hex: str = Field(..., min_length=128, max_length=128)

    def signing_bytes(self) -> bytes:
        payload = {
            "schema_version": self.schema_version,
            "approval_id": self.approval_id,
            "tenant_id": self.tenant_id,
            "request_id": self.request_id,
            "request_hash": self.request_hash,
            "approver_subject": self.approver_subject,
            "approver_principal_type": self.approver_principal_type.value,
            "approver_key_id": self.approver_key_id,
            "justification": self.justification,
            "approved_at_utc": self.approved_at_utc,
            "expires_at_utc": self.expires_at_utc,
        }
        return DOMAIN_APPROVAL_V1 + canonicalize_jcs_bytes(payload)


class SignedReceipt(ImmutableContractModel):
    schema_version: str = Field(default="sentinel.receipt.v1")
    receipt_id: UUID
    tenant_id: UUID
    request_id: UUID
    idempotency_key: str = Field(..., min_length=8, max_length=128)
    request_hash: str = Field(..., min_length=64, max_length=64)
    canonical_args_hash: str = Field(..., min_length=64, max_length=64)
    policy_bundle_hash: str = Field(..., min_length=64, max_length=64)
    decision: PolicyDecisionType
    reason_code: str = Field(..., min_length=2, max_length=128)
    approval_id: UUID | None = None
    execution_state: ExecutionState
    redacted_fields: tuple[str, ...] = Field(default_factory=tuple)
    signing_key_id: str = Field(..., min_length=3, max_length=128)
    evaluated_at_utc: datetime
    ed25519_signature_hex: str = Field(..., min_length=128, max_length=128)

    @classmethod
    def build_unsigned(
        cls,
        receipt_id: UUID,
        request: ToolCallRequest,
        decision: PolicyDecision,
        execution_state: ExecutionState,
        redacted_fields: tuple[str, ...],
        approval_id: UUID | None,
        signing_key_id: str,
        evaluated_at_utc: datetime,
    ) -> Self:
        return cls(
            receipt_id=receipt_id,
            tenant_id=request.identity.tenant_id,
            request_id=request.request_id,
            idempotency_key=request.idempotency_key,
            request_hash=request.request_hash,
            canonical_args_hash=request.canonical_args_hash,
            policy_bundle_hash=decision.policy_bundle_hash,
            decision=decision.decision,
            reason_code=decision.reason_code,
            approval_id=approval_id,
            execution_state=execution_state,
            redacted_fields=redacted_fields,
            signing_key_id=signing_key_id,
            evaluated_at_utc=evaluated_at_utc,
            ed25519_signature_hex="0" * 128,
        )

    def with_signature(self, signature_hex: str) -> Self:
        data = self.model_dump()
        data["ed25519_signature_hex"] = signature_hex
        return self.__class__.model_validate(data)

    def signing_bytes(self) -> bytes:
        payload = {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "tenant_id": self.tenant_id,
            "request_id": self.request_id,
            "idempotency_key": self.idempotency_key,
            "request_hash": self.request_hash,
            "canonical_args_hash": self.canonical_args_hash,
            "policy_bundle_hash": self.policy_bundle_hash,
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "approval_id": self.approval_id,
            "execution_state": self.execution_state.value,
            "redacted_fields": list(self.redacted_fields),
            "signing_key_id": self.signing_key_id,
            "evaluated_at_utc": self.evaluated_at_utc,
        }
        return DOMAIN_RECEIPT_V1 + canonicalize_jcs_bytes(payload)

    @property
    def receipt_leaf_bytes(self) -> bytes:
        return self.signing_bytes() + bytes.fromhex(self.ed25519_signature_hex)


class EvidenceManifest(ImmutableContractModel):
    schema_version: str = Field(default="sentinel.manifest.v1")
    manifest_id: UUID
    tenant_id: UUID
    batch_sequence_number: int = Field(..., ge=1)
    previous_manifest_hash: str = Field(..., min_length=64, max_length=64)
    merkle_root_hex: str = Field(..., min_length=64, max_length=64)
    leaf_count: int = Field(..., ge=1)
    receipt_ids: tuple[UUID, ...] = Field(..., min_length=1)
    s3_worm_object_key: str = Field(..., min_length=3, max_length=512)
    s3_version_id: str | None = None
    signing_key_id: str = Field(..., min_length=3, max_length=128)
    sealed_at_utc: datetime
    ed25519_signature_hex: str = Field(..., min_length=128, max_length=128)

    def signing_bytes(self) -> bytes:
        payload = {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "tenant_id": self.tenant_id,
            "batch_sequence_number": self.batch_sequence_number,
            "previous_manifest_hash": self.previous_manifest_hash,
            "merkle_root_hex": self.merkle_root_hex,
            "leaf_count": self.leaf_count,
            "receipt_ids": list(self.receipt_ids),
            "s3_worm_object_key": self.s3_worm_object_key,
            "signing_key_id": self.signing_key_id,
            "sealed_at_utc": self.sealed_at_utc,
        }
        return DOMAIN_MANIFEST_V1 + canonicalize_jcs_bytes(payload)

    @property
    def manifest_hash(self) -> str:
        return hashlib.sha256(
            self.signing_bytes() + bytes.fromhex(self.ed25519_signature_hex)
        ).hexdigest()


class TrustStoreKeyEntry(ImmutableContractModel):
    """Public key state carried inside an exported verification package."""

    key_id: str
    principal_type: PrincipalType
    public_key_hex: str
    status: KeyLifecycleStatus
    valid_from_utc: datetime
    valid_until_utc: datetime | None = None
    compromised_after_utc: datetime | None = None


@dataclass(frozen=True)
class VerificationReport:
    """Result of one offline verification."""

    is_valid: bool
    violations: tuple[str, ...]
