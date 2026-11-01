"""Offline sentinel-verify command. No database and no network."""

import argparse
import json
import sys
from pathlib import Path

from packages.independent_verifier.verifier import IndependentAuditVerifier
from packages.protocol_contracts.models import (
    ApprovalRecord,
    EvidenceManifest,
    SignedReceipt,
    TrustStoreKeyEntry,
)

GENESIS_PREVIOUS_MANIFEST_HASH: str = "0" * 64


def load_trust_store(path: Path) -> dict[str, TrustStoreKeyEntry]:
    raw_data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw_data, list):
        items = raw_data
    elif "keys" in raw_data and isinstance(raw_data["keys"], list):
        items = raw_data["keys"]
    elif "keys" in raw_data and isinstance(raw_data["keys"], dict):
        items = list(raw_data["keys"].values())
    else:
        items = list(raw_data.values())
    store: dict[str, TrustStoreKeyEntry] = {}
    for item in items:
        entry = TrustStoreKeyEntry.model_validate_json(json.dumps(item))
        store[entry.key_id] = entry
    return store


def chain_violations(
    verifier: IndependentAuditVerifier,
    manifest: EvidenceManifest,
    previous: EvidenceManifest | None,
    consistency_proof: object,
) -> list[str]:
    """Checks the genesis head, or the previous hash plus the RFC 6962 consistency proof."""
    if previous is None:
        if (
            manifest.batch_sequence_number != 1
            or manifest.previous_manifest_hash != GENESIS_PREVIOUS_MANIFEST_HASH
        ):
            return ["CHAIN_HEAD_WITHOUT_PREVIOUS_MANIFEST"]
        return []
    found: list[str] = []
    if manifest.previous_manifest_hash != previous.manifest_hash:
        found.append("PREVIOUS_MANIFEST_HASH_MISMATCH")
    if not isinstance(consistency_proof, list) or not all(
        isinstance(item, str) for item in consistency_proof
    ):
        found.append("RFC6962_CHAIN_CONSISTENCY_FAILED")
        return found
    if not verifier.verify_tree_consistency(previous, manifest, list(consistency_proof)):
        found.append("RFC6962_CHAIN_CONSISTENCY_FAILED")
    return found


def _write_result(document: dict[str, object], exit_code: int) -> int:
    sys.stdout.write(json.dumps(document, indent=2) + "\n")
    return exit_code


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-verify",
        description="Sentinel offline verifier for a receipt and an evidence manifest.",
    )
    parser.add_argument("--trust-store", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, default=None)
    parser.add_argument("--receipt", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--proof", type=Path, default=None)
    parser.add_argument("--approval", type=Path, default=None)
    parser.add_argument("--previous-manifest", type=Path, default=None)
    parser.add_argument("--consistency-proof", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        trust_store = load_trust_store(args.trust_store)
        verifier = IndependentAuditVerifier(trust_store=trust_store)
        prev_manifest: EvidenceManifest | None = None
        if args.previous_manifest is not None:
            prev_raw = json.loads(args.previous_manifest.read_text(encoding="utf-8"))
            prev_manifest = EvidenceManifest.model_validate_json(
                json.dumps(prev_raw.get("manifest", prev_raw))
            )
        proof_from_flag: object = None
        if args.consistency_proof is not None:
            proof_from_flag = json.loads(args.consistency_proof.read_text(encoding="utf-8"))
        if args.bundle is not None:
            bundle_data = json.loads(args.bundle.read_text(encoding="utf-8"))
            manifest = EvidenceManifest.model_validate_json(json.dumps(bundle_data["manifest"]))
            if prev_manifest is None and isinstance(bundle_data.get("previous_manifest"), dict):
                prev_manifest = EvidenceManifest.model_validate_json(
                    json.dumps(bundle_data["previous_manifest"])
                )
            entries = bundle_data.get("entries", [])
            if len(entries) != manifest.leaf_count:
                return _write_result(
                    {"status": "FAILED", "violations": ["LEAF_COUNT_MISMATCH"]},
                    1,
                )
            all_violations: list[str] = []
            for item in entries:
                receipt = SignedReceipt.model_validate_json(json.dumps(item["receipt"]))
                approval = (
                    ApprovalRecord.model_validate_json(json.dumps(item["approval"]))
                    if item.get("approval") is not None
                    else None
                )
                audit_path: list[tuple[str, str]] = [
                    (str(node["side"]), str(node["hash_hex"])) for node in item["audit_path"]
                ]
                report = verifier.verify_receipt_and_inclusion(
                    receipt=receipt,
                    audit_path=audit_path,
                    manifest=manifest,
                    approval=approval,
                    previous_manifest=prev_manifest,
                )
                if not report.is_valid:
                    all_violations.extend(f"{receipt.receipt_id}:{v}" for v in report.violations)
            proof_raw = (
                proof_from_flag
                if proof_from_flag is not None
                else bundle_data.get("consistency_proof")
            )
            all_violations.extend(chain_violations(verifier, manifest, prev_manifest, proof_raw))
            is_ok = len(all_violations) == 0
            return _write_result(
                {
                    "status": "VERIFIED" if is_ok else "FAILED",
                    "manifest_id": str(manifest.manifest_id),
                    "merkle_root_hex": manifest.merkle_root_hex,
                    "violations": all_violations,
                },
                0 if is_ok else 1,
            )
        if args.receipt is None or args.manifest is None or args.proof is None:
            parser.error("Provide either --bundle OR (--receipt, --manifest, and --proof).")
        receipt = SignedReceipt.model_validate_json(args.receipt.read_text(encoding="utf-8"))
        manifest = EvidenceManifest.model_validate_json(args.manifest.read_text(encoding="utf-8"))
        raw_proof = json.loads(args.proof.read_text(encoding="utf-8"))
        audit_path = [
            (str(step["side"]), str(step["hash_hex"]))
            if isinstance(step, dict)
            else (str(step[0]), str(step[1]))
            for step in raw_proof
        ]
        approval = (
            ApprovalRecord.model_validate_json(args.approval.read_text(encoding="utf-8"))
            if args.approval is not None
            else None
        )
        report = verifier.verify_receipt_and_inclusion(
            receipt=receipt,
            audit_path=audit_path,
            manifest=manifest,
            approval=approval,
            previous_manifest=prev_manifest,
        )
        violations = list(report.violations)
        violations.extend(chain_violations(verifier, manifest, prev_manifest, proof_from_flag))
        is_ok = len(violations) == 0
        return _write_result(
            {
                "status": "VERIFIED" if is_ok else "FAILED",
                "receipt_id": str(receipt.receipt_id),
                "manifest_id": str(manifest.manifest_id),
                "merkle_root_hex": manifest.merkle_root_hex,
                "violations": violations,
            },
            0 if is_ok else 1,
        )
    except Exception as exc:  # noqa: BLE001
        return _write_result(
            {"status": "FAILED", "violations": [f"DESERIALIZATION_ERROR: {exc}"]},
            1,
        )


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
