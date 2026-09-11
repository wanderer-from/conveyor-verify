"""RFC 6962 / RFC 9162 Merkle trees over log record hashes (integrity.md §5).

Leaves are record-hash bytes; `leaf_hash` applies the 0x00 prefix, `node_hash`
the 0x01 prefix. Trees are built over the whole log, never per window. Proof
generation follows RFC 9162 §2.1.3.1 / §2.1.4.1; verification follows
§2.1.3.2 / §2.1.4.2.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

Hash = bytes


def _sha256(*parts: bytes) -> Hash:
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def leaf_hash(data: bytes) -> Hash:
    """MTH({d}) = SHA-256(0x00 || d)."""
    return _sha256(b"\x00", data)


def node_hash(left: Hash, right: Hash) -> Hash:
    """SHA-256(0x01 || left || right)."""
    return _sha256(b"\x01", left, right)


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << (n - 1).bit_length() - 1


def root_hash(leaves: Sequence[bytes]) -> Hash:
    """Merkle tree hash of the leaf inputs; SHA-256("") for the empty tree."""
    n = len(leaves)
    if n == 0:
        return _sha256()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _split(n)
    return node_hash(root_hash(leaves[:k]), root_hash(leaves[k:]))


def inclusion_proof(leaves: Sequence[bytes], index: int) -> list[Hash]:
    """Audit path for leaf `index` in the tree over `leaves` (RFC 9162 §2.1.3.1)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(f"leaf index {index} out of range for tree size {n}")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return [*inclusion_proof(leaves[:k], index), root_hash(leaves[k:])]
    return [*inclusion_proof(leaves[k:], index - k), root_hash(leaves[:k])]


def verify_inclusion(leaf: Hash, index: int, tree_size: int, proof: Sequence[Hash], root: Hash) -> bool:
    """RFC 9162 §2.1.3.2. `leaf` is the leaf hash (already 0x00-prefixed)."""
    if index < 0 or tree_size <= 0 or index >= tree_size:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _subproof(m: int, leaves: Sequence[bytes], complete: bool) -> list[Hash]:
    n = len(leaves)
    if m == n:
        return [] if complete else [root_hash(leaves)]
    k = _split(n)
    if m <= k:
        return [*_subproof(m, leaves[:k], complete), root_hash(leaves[k:])]
    return [*_subproof(m - k, leaves[k:], False), root_hash(leaves[:k])]


def consistency_proof(leaves: Sequence[bytes], first: int, second: int) -> list[Hash]:
    """Proof that the tree of size `first` is a prefix of the tree of size `second`."""
    if not 0 <= first <= second <= len(leaves):
        raise IndexError(f"invalid sizes first={first} second={second} for {len(leaves)} leaves")
    if first in (0, second):
        return []
    return _subproof(first, leaves[:second], True)


def verify_consistency(
    first: int, second: int, proof: Sequence[Hash], first_root: Hash, second_root: Hash
) -> bool:
    """RFC 9162 §2.1.4.2."""
    if first < 0 or second < first:
        return False
    if first == second:
        return len(proof) == 0 and first_root == second_root
    if first == 0:
        return len(proof) == 0
    path = list(proof)
    if first & (first - 1) == 0:  # first is a power of two: its root is implied
        path = [first_root, *path]
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root
