"""SHA-256 with the domain-separation prefixes of integrity.md §2."""

from __future__ import annotations

import hashlib
from enum import StrEnum

from conveyor_verify.vendored.canon import Json, canonicalize

ZERO_HASH = "0" * 64
"""prev_hash of the first log row."""


class Domain(StrEnum):
    """Domain-separation prefixes. Frozen; new subjects are added, never changed."""

    LOG_RECORD = "conveyor/v1/record\n"
    SIGNATURE = "conveyor/v1/sig\n"
    RECORD = "conveyor/v1/rec\n"
    REGISTRY_CHANGE = "conveyor/v1/rchange\n"
    DOCUMENT = "conveyor/v1/doc\n"
    PROBE = "conveyor/v1/probe\n"
    RECEIPT = "conveyor/v1/receipt\n"
    # Forms referenced by the record_type catalog (integrity.md §3) but not given a prefix
    # there; added 2026-09-11 (additive, see ARCHITECTURE.md #30).
    KEY = "conveyor/v1/key\n"
    CORRECTION = "conveyor/v1/correction\n"
    ACTION = "conveyor/v1/action\n"
    BLOCK = "conveyor/v1/block\n"


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256."""
    return hashlib.sha256(data).hexdigest()


def content_hash(domain: Domain, content: Json) -> str:
    """Hash of a canonical content form under its subject prefix.

    For `document_published` the spec hashes JCS(content) without a prefix
    string other than `conveyor/v1/doc\\n`; callers pass Domain.DOCUMENT.
    """
    if domain in (Domain.LOG_RECORD, Domain.SIGNATURE):
        raise ValueError("content_hash takes a subject prefix, not the log or signature domain")
    return sha256_hex(domain.encode() + canonicalize(content))


def record_hash(envelope: Json) -> str:
    """record_hash = SHA256(b"conveyor/v1/record\\n" + JCS(envelope))."""
    return sha256_hex(Domain.LOG_RECORD.encode() + canonicalize(envelope))


def hex_to_bytes(hex64: str) -> bytes:
    """Decode a lowercase 64-char hex hash; reject anything else."""
    if len(hex64) != 64 or hex64 != hex64.lower():
        raise ValueError("hash must be 64 lowercase hex characters")
    return bytes.fromhex(hex64)
