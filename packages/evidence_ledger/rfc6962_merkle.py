"""RFC 6962 Merkle tree. An odd leaf count is not padded by duplicating the last leaf."""

import hashlib
import hmac

LEAF_PREFIX: bytes = b"\x00"
NODE_PREFIX: bytes = b"\x01"


def largest_power_of_two_less_than(n: int) -> int:
    """Computes k = 2^(floor(log2(n - 1))) for n > 1 per RFC 6962 Section 2.1."""
    if n <= 1:
        raise ValueError("n must be strictly greater than 1.")
    return 1 << ((n - 1).bit_length() - 1)


def leaf_hash(leaf_bytes: bytes) -> bytes:
    """Computes RFC 6962 leaf hash: SHA-256(0x00 || leaf_bytes)."""
    return hashlib.sha256(LEAF_PREFIX + leaf_bytes).digest()


def node_hash(left_hash: bytes, right_hash: bytes) -> bytes:
    """Computes RFC 6962 internal node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(NODE_PREFIX + left_hash + right_hash).digest()


def merkle_tree_hash(leaves: list[bytes]) -> bytes:
    """Computes the exact Merkle Tree Hash (MTH) per RFC 6962 Section 2.1."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = largest_power_of_two_less_than(n)
    return node_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))


def inclusion_proof(index: int, leaves: list[bytes]) -> list[tuple[str, str]]:
    """Generates RFC 6962 Audit Path (inclusion proof) for leaf at index."""
    n = len(leaves)
    if not (0 <= index < n):
        raise IndexError(f"Leaf index {index} out of range for tree of size {n}.")
    if n == 1:
        return []
    k = largest_power_of_two_less_than(n)
    if index < k:
        path = inclusion_proof(index, leaves[:k])
        path.append(("R", merkle_tree_hash(leaves[k:]).hex()))
        return path
    path = inclusion_proof(index - k, leaves[k:])
    path.append(("L", merkle_tree_hash(leaves[:k]).hex()))
    return path


def verify_inclusion_proof(
    leaf_bytes: bytes,
    audit_path: list[tuple[str, str]],
    expected_root_hex: str,
) -> bool:
    """Verifies an RFC 6962 inclusion proof in constant-time digest comparison."""
    try:
        expected_root = bytes.fromhex(expected_root_hex)
    except ValueError:
        return False
    current_hash = leaf_hash(leaf_bytes)
    for side, sibling_hex in audit_path:
        try:
            sibling_bytes = bytes.fromhex(sibling_hex)
        except ValueError:
            return False
        if len(sibling_bytes) != 32:
            return False
        if side == "R":
            current_hash = node_hash(current_hash, sibling_bytes)
        elif side == "L":
            current_hash = node_hash(sibling_bytes, current_hash)
        else:
            return False
    return hmac.compare_digest(current_hash, expected_root)


def consistency_proof(m: int, leaves: list[bytes]) -> list[str]:
    """Generates RFC 6962 Section 2.1.2 Consistency Proof for prefix size m."""
    n = len(leaves)
    if not (1 <= m <= n):
        raise ValueError(f"Invalid prefix size m={m} for tree of size n={n}.")
    if m == n:
        return []
    return [h.hex() for h in _subproof(m, leaves, True)]


def _subproof(m: int, leaves: list[bytes], is_complete_subroot: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if is_complete_subroot else [merkle_tree_hash(leaves)]
    k = largest_power_of_two_less_than(n)
    if m <= k:
        proof = _subproof(m, leaves[:k], is_complete_subroot)
        proof.append(merkle_tree_hash(leaves[k:]))
        return proof
    proof = _subproof(m - k, leaves[k:], False)
    proof.append(merkle_tree_hash(leaves[:k]))
    return proof


def verify_consistency_proof(
    first_size: int,
    second_size: int,
    first_root_hex: str,
    second_root_hex: str,
    proof_hex_list: list[str],
) -> bool:
    """Verifies RFC 6962 Section 2.1.2 Consistency Proof offline in constant time."""
    if not (1 <= first_size <= second_size):
        return False
    try:
        first_root = bytes.fromhex(first_root_hex)
        second_root = bytes.fromhex(second_root_hex)
        proof_bytes = [bytes.fromhex(h) for h in proof_hex_list]
    except ValueError:
        return False
    if len(first_root) != 32 or len(second_root) != 32 or any(len(p) != 32 for p in proof_bytes):
        return False
    if first_size == second_size:
        return len(proof_bytes) == 0 and hmac.compare_digest(first_root, second_root)
    proof_iter = iter(proof_bytes)

    def _reconstruct(
        sub_m: int, sub_n: int, is_complete_subroot: bool
    ) -> tuple[bytes, bytes]:
        if sub_m == sub_n:
            if is_complete_subroot:
                return first_root, first_root
            h = next(proof_iter)
            return h, h
        k = largest_power_of_two_less_than(sub_n)
        if sub_m <= k:
            old_left, new_left = _reconstruct(sub_m, k, is_complete_subroot)
            right_hash = next(proof_iter)
            return old_left, node_hash(new_left, right_hash)
        old_right, new_right = _reconstruct(sub_m - k, sub_n - k, False)
        left_hash = next(proof_iter)
        return node_hash(left_hash, old_right), node_hash(left_hash, new_right)

    try:
        computed_old, computed_new = _reconstruct(first_size, second_size, True)
        try:
            next(proof_iter)
            return False
        except StopIteration:
            return hmac.compare_digest(computed_old, first_root) and hmac.compare_digest(
                computed_new, second_root
            )
    except StopIteration:
        return False
