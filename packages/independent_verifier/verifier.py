"""Offline verifier. It reads exported artifacts and does not open a socket."""

from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from packages.evidence_ledger.rfc6962_merkle import (
    verify_consistency_proof,
    verify_inclusion_proof,
)
from packages.protocol_contracts.models import (
    ApprovalRecord,
    EvidenceManifest,
    KeyLifecycleStatus,
    PolicyDecisionType,
    PrincipalType,
    SignedReceipt,
    TrustStoreKeyEntry,
    VerificationReport,
)


class IndependentAuditVerifier:
    """Checks a signed receipt, its inclusion proof, and the manifest signature."""

    def __init__(self, trust_store: dict[str, TrustStoreKeyEntry]) -> None:
        self._trust_store = trust_store

    def verify_key_at_timestamp(
        self,
        key_id: str,
        signed_at_utc: datetime,
        expected_principal_type: PrincipalType,
    ) -> tuple[bool, str]:
        entry = self._trust_store.get(key_id)
        if entry is None:
            return False, f"UNKNOWN_SIGNING_KEY: {key_id}"
        if entry.principal_type != expected_principal_type:
            return False, f"KEY_PRINCIPAL_TYPE_MISMATCH: {key_id}"
        if signed_at_utc < entry.valid_from_utc:
            return False, f"SIGNATURE_BEFORE_KEY_VALIDITY: {key_id}"
        if entry.valid_until_utc is not None and signed_at_utc > entry.valid_until_utc:
            return False, f"SIGNATURE_AFTER_KEY_EXPIRATION: {key_id}"
        if entry.status == KeyLifecycleStatus.COMPROMISED:  # noqa: SIM102
            if entry.compromised_after_utc is None or signed_at_utc >= entry.compromised_after_utc:
                return False, f"KEY_COMPROMISED_AT_SIGNING_TIME: {key_id}"
        return True, "OK"

    def verify_ed25519(self, key_id: str, message: bytes, signature_hex: str) -> bool:
        entry = self._trust_store.get(key_id)
        if entry is None:
            return False
        try:
            pub_bytes = bytes.fromhex(entry.public_key_hex)
            sig_bytes = bytes.fromhex(signature_hex)
            pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub_key.verify(sig_bytes, message)
            return True
        except (ValueError, InvalidSignature):
            return False

    def verify_tree_consistency(
        self,
        older_manifest: EvidenceManifest,
        newer_manifest: EvidenceManifest,
        consistency_proof_hex: list[str],
    ) -> bool:
        if older_manifest.tenant_id != newer_manifest.tenant_id:
            return False
        return verify_consistency_proof(
            first_size=older_manifest.leaf_count,
            second_size=newer_manifest.leaf_count,
            first_root_hex=older_manifest.merkle_root_hex,
            second_root_hex=newer_manifest.merkle_root_hex,
            proof_hex_list=consistency_proof_hex,
        )

    def verify_receipt_and_inclusion(
        self,
        receipt: SignedReceipt,
        audit_path: list[tuple[str, str]],
        manifest: EvidenceManifest,
        approval: ApprovalRecord | None = None,
        previous_manifest: EvidenceManifest | None = None,
    ) -> VerificationReport:
        violations: list[str] = []
        if receipt.tenant_id != manifest.tenant_id:
            violations.append("TENANT_MISMATCH_RECEIPT_VS_MANIFEST")
        key_ok, key_reason = self.verify_key_at_timestamp(
            receipt.signing_key_id, receipt.evaluated_at_utc, PrincipalType.WORKLOAD
        )
        if not key_ok:
            violations.append(f"RECEIPT_KEY_INVALID: {key_reason}")
        elif not self.verify_ed25519(
            receipt.signing_key_id, receipt.signing_bytes(), receipt.ed25519_signature_hex
        ):
            violations.append("RECEIPT_ED25519_SIGNATURE_INVALID")
        if receipt.decision == PolicyDecisionType.REQUIRE_APPROVAL:
            if approval is None:
                violations.append("MISSING_REQUIRED_HUMAN_APPROVAL_RECORD")
            else:
                if approval.request_hash != receipt.request_hash:
                    violations.append("APPROVAL_REQUEST_HASH_MISMATCH")
                if approval.tenant_id != receipt.tenant_id:
                    violations.append("APPROVAL_TENANT_MISMATCH")
                if approval.approved_at_utc > approval.expires_at_utc:
                    violations.append("APPROVAL_ALREADY_EXPIRED")
                appr_key_ok, appr_reason = self.verify_key_at_timestamp(
                    approval.approver_key_id,
                    approval.approved_at_utc,
                    PrincipalType.HUMAN_APPROVER,
                )
                if not appr_key_ok:
                    violations.append(f"APPROVAL_KEY_INVALID: {appr_reason}")
                elif not self.verify_ed25519(
                    approval.approver_key_id,
                    approval.signing_bytes(),
                    approval.ed25519_signature_hex,
                ):
                    violations.append("APPROVAL_ED25519_SIGNATURE_INVALID")
        mfst_key_ok, mfst_reason = self.verify_key_at_timestamp(
            manifest.signing_key_id, manifest.sealed_at_utc, PrincipalType.CUSTODY_LEDGER
        )
        if not mfst_key_ok:
            violations.append(f"MANIFEST_KEY_INVALID: {mfst_reason}")
        elif not self.verify_ed25519(
            manifest.signing_key_id, manifest.signing_bytes(), manifest.ed25519_signature_hex
        ):
            violations.append("MANIFEST_ED25519_SIGNATURE_INVALID")
        if not verify_inclusion_proof(
            receipt.receipt_leaf_bytes, audit_path, manifest.merkle_root_hex
        ):
            violations.append("RFC6962_MERKLE_INCLUSION_PROOF_FAILED")
        if previous_manifest is not None:  # noqa: SIM102
            if manifest.batch_sequence_number != previous_manifest.batch_sequence_number + 1:
                violations.append("BATCH_SEQUENCE_GAP_DETECTED")
        return VerificationReport(is_valid=len(violations) == 0, violations=tuple(violations))
