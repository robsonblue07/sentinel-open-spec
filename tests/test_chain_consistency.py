"""The CLI must reject a later batch whose RFC 6962 consistency proof does not match."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.cli_verifier.main import run_cli
from packages.evidence_ledger.rfc6962_merkle import (
    consistency_proof,
    inclusion_proof,
    merkle_tree_hash,
)
from packages.protocol_contracts.models import (
    EvidenceManifest,
    ExecutionState,
    OperationClass,
    PolicyDecision,
    PolicyDecisionType,
    PrincipalType,
    SignedReceipt,
    ToolCallRequest,
    WorkloadIdentity,
)

_SIGNED_AT = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
_TENANT = UUID("11111111-1111-4111-8111-111111111111")


def _receipt(private_key: Ed25519PrivateKey, suffix: str) -> SignedReceipt:
    identity = WorkloadIdentity(
        tenant_id=_TENANT,
        subject="agent-finops-01",
        issuer="https://auth.sentinel.internal",
        audience="sentinel-mcp-gateway",
        scopes=frozenset({"mcp:tools:read"}),
    )
    request = ToolCallRequest(
        request_id=UUID(f"22222222-2222-4222-8222-22222222222{suffix}"),
        correlation_id=UUID(f"33333333-3333-4333-8333-33333333333{suffix}"),
        idempotency_key=f"idem-chain-{suffix}",
        identity=identity,
        tool_name="read_ledger_balance",
        operation_class=OperationClass.READ_ONLY,
        resource_uri="mcp://ledger.sentinel.internal/accounts/42",
        arguments={"amount_cents": 1999},
        requested_at_utc=_SIGNED_AT,
    )
    decision = PolicyDecision(
        decision=PolicyDecisionType.ALLOW,
        reason_code="READ_ONLY_SCOPE_AUTHORIZED",
        policy_bundle_hash="c" * 64,
    )
    unsigned = SignedReceipt.build_unsigned(
        receipt_id=UUID(f"44444444-4444-4444-8444-44444444444{suffix}"),
        request=request,
        decision=decision,
        execution_state=ExecutionState.SUCCEEDED,
        redacted_fields=(),
        approval_id=None,
        signing_key_id="workload-key-v1",
        evaluated_at_utc=_SIGNED_AT,
    )
    return unsigned.with_signature(private_key.sign(unsigned.signing_bytes()).hex())


def _manifest(
    receipt_ids: tuple[UUID, ...],
    leaves: list[bytes],
    sequence: int,
    previous_hash: str,
    custody_key: Ed25519PrivateKey,
    manifest_id: UUID,
) -> EvidenceManifest:
    unsigned = EvidenceManifest(
        manifest_id=manifest_id,
        tenant_id=_TENANT,
        batch_sequence_number=sequence,
        previous_manifest_hash=previous_hash,
        merkle_root_hex=merkle_tree_hash(leaves).hex(),
        leaf_count=len(leaves),
        receipt_ids=receipt_ids,
        s3_worm_object_key=f"worm-custody/example/seq={sequence:012d}",
        signing_key_id="custody-ledger-key-v1",
        sealed_at_utc=_SIGNED_AT,
        ed25519_signature_hex="0" * 128,
    )
    signature = custody_key.sign(unsigned.signing_bytes()).hex()
    return EvidenceManifest.model_validate(
        {**unsigned.model_dump(), "ed25519_signature_hex": signature}
    )


def _bundle(
    directory: Path,
    manifest: EvidenceManifest,
    receipts: list[SignedReceipt],
    leaves: list[bytes],
    previous: EvidenceManifest | None,
    proof: list[str] | None,
    workload: Ed25519PrivateKey,
    custody: Ed25519PrivateKey,
) -> Path:
    entries = []
    for index, receipt in enumerate(receipts):
        entries.append(
            {
                "receipt": json.loads(receipt.model_dump_json()),
                "audit_path": [
                    {"side": side, "hash_hex": sibling}
                    for side, sibling in inclusion_proof(index, leaves)
                ],
            }
        )
    document: dict[str, object] = {
        "manifest": json.loads(manifest.model_dump_json()),
        "entries": entries,
        "keys": [
            {
                "key_id": "workload-key-v1",
                "principal_type": PrincipalType.WORKLOAD.value,
                "public_key_hex": workload.public_key().public_bytes_raw().hex(),
                "status": "ACTIVE",
                "valid_from_utc": (_SIGNED_AT - timedelta(days=30)).isoformat(),
            },
            {
                "key_id": "custody-ledger-key-v1",
                "principal_type": PrincipalType.CUSTODY_LEDGER.value,
                "public_key_hex": custody.public_key().public_bytes_raw().hex(),
                "status": "ACTIVE",
                "valid_from_utc": (_SIGNED_AT - timedelta(days=30)).isoformat(),
            },
        ],
    }
    if previous is not None:
        document["previous_manifest"] = json.loads(previous.model_dump_json())
    if proof is not None:
        document["consistency_proof"] = proof
    path = directory / "bundle.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_bad_consistency_proof_fails(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workload = Ed25519PrivateKey.generate()
    custody = Ed25519PrivateKey.generate()
    first = _receipt(workload, "1")
    second = _receipt(workload, "2")
    leaves = [first.receipt_leaf_bytes, second.receipt_leaf_bytes]
    older = _manifest(
        (first.receipt_id,),
        [first.receipt_leaf_bytes],
        1,
        "0" * 64,
        custody,
        UUID("55555555-5555-4555-8555-555555555551"),
    )
    newer = _manifest(
        (first.receipt_id, second.receipt_id),
        leaves,
        2,
        older.manifest_hash,
        custody,
        UUID("55555555-5555-4555-8555-555555555552"),
    )
    proof = consistency_proof(1, leaves)
    broken = [*proof, "00" * 32]
    bundle = _bundle(tmp_path, newer, [first, second], leaves, older, broken, workload, custody)
    code = run_cli(["--trust-store", str(bundle), "--bundle", str(bundle)])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "FAILED"
    assert any("CHAIN_CONSISTENCY" in item for item in payload["violations"])


def test_consistency_proof_accepts_a_growing_prefix(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    workload = Ed25519PrivateKey.generate()
    custody = Ed25519PrivateKey.generate()
    first = _receipt(workload, "1")
    second = _receipt(workload, "2")
    leaves = [first.receipt_leaf_bytes, second.receipt_leaf_bytes]
    older = _manifest(
        (first.receipt_id,),
        [first.receipt_leaf_bytes],
        1,
        "0" * 64,
        custody,
        UUID("55555555-5555-4555-8555-555555555551"),
    )
    newer = _manifest(
        (first.receipt_id, second.receipt_id),
        leaves,
        2,
        older.manifest_hash,
        custody,
        UUID("55555555-5555-4555-8555-555555555552"),
    )
    bundle = _bundle(
        tmp_path,
        newer,
        [first, second],
        leaves,
        older,
        consistency_proof(1, leaves),
        workload,
        custody,
    )
    code = run_cli(["--trust-store", str(bundle), "--bundle", str(bundle)])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "VERIFIED"
    assert payload["violations"] == []
