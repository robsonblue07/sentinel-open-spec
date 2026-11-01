"""RFC 6962 vectors. An odd leaf count must not be padded by copying the last leaf."""

from packages.evidence_ledger.rfc6962_merkle import (
    consistency_proof,
    inclusion_proof,
    merkle_tree_hash,
    verify_consistency_proof,
    verify_inclusion_proof,
)


def test_rfc6962_odd_leaf_is_not_duplicated() -> None:
    leaves_3 = [b"leaf-A", b"leaf-B", b"leaf-C"]
    leaves_4_dup = [b"leaf-A", b"leaf-B", b"leaf-C", b"leaf-C"]
    assert merkle_tree_hash(leaves_3) != merkle_tree_hash(leaves_4_dup)
    root_hex = merkle_tree_hash(leaves_3).hex()
    proof = inclusion_proof(2, leaves_3)
    assert verify_inclusion_proof(b"leaf-C", proof, root_hex) is True


def test_rfc6962_consistency_proof_for_prefix_of_seven() -> None:
    leaves = [f"leaf-{index}".encode() for index in range(7)]
    old_root = merkle_tree_hash(leaves[:3]).hex()
    new_root = merkle_tree_hash(leaves).hex()
    proof = consistency_proof(3, leaves)
    assert verify_consistency_proof(3, 7, old_root, new_root, proof) is True
    assert verify_consistency_proof(3, 7, old_root, new_root, [*proof, "00" * 32]) is False
