"""Offline verification of an integrity log export (integrity.md §7, steps 1-3).

The verifier consumes rows as `(envelope dict, signature)` in seq order plus a
key history and reports every failure with its seq and category. Trees and
anchors (steps 4-6) live in `merkle` and the anchor modules.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from conveyor_verify.vendored.envelope import LogEnvelope, RecordType
from conveyor_verify.vendored.hashing import ZERO_HASH


class Failure(StrEnum):
    ENVELOPE = "envelope"  # does not parse as a closed v1 envelope
    HASH = "hash"  # stored record_hash != recomputed
    GAP = "gap"  # seq not previous + 1
    CHAIN = "chain"  # prev_hash != previous record_hash
    SIGNATURE = "signature"  # signature invalid under the key active at ts
    KEY = "key"  # key_id unknown, not yet valid, or revoked at ts
    DISPUTED = "disputed"  # valid, but inside a compromise-suspected window


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    public_key_b64: str
    not_before: str  # RFC 3339 Z, lexically comparable
    revoked_at: str | None = None
    compromise_suspected_from: str | None = None


@dataclass(frozen=True)
class Finding:
    seq: int
    category: Failure
    detail: str


@dataclass
class ChainReport:
    rows: int = 0
    findings: list[Finding] = field(default_factory=list)
    last_record_hash: str = ZERO_HASH
    record_hashes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(f.category is not Failure.DISPUTED for f in self.findings)


KeyLookup = Callable[[str], KeyRecord | None]


def keys_from_log(rows: Iterable[tuple[dict[str, Any], str]]) -> dict[str, KeyRecord]:
    """Rebuild key history from key_registered / key_revoked rows.

    The row's `content_hash` is over the key form; the public key itself is
    carried in the row payload by the exporter under `public_key`.
    """
    keys: dict[str, KeyRecord] = {}
    for env_dict, _sig in rows:
        rt = env_dict.get("record_type")
        payload = env_dict.get("payload") or {}
        if rt == RecordType.KEY_REGISTERED and "public_key" in payload:
            keys[env_dict["subject_id"]] = KeyRecord(
                key_id=env_dict["subject_id"],
                public_key_b64=payload["public_key"],
                not_before=env_dict["ts"],
            )
        elif rt == RecordType.KEY_REVOKED and env_dict.get("subject_id") in keys:
            old = keys[env_dict["subject_id"]]
            keys[old.key_id] = KeyRecord(
                key_id=old.key_id,
                public_key_b64=old.public_key_b64,
                not_before=old.not_before,
                revoked_at=env_dict["ts"],
                compromise_suspected_from=payload.get("compromise_suspected_from"),
            )
    return keys


def verify_chain(
    rows: Iterable[tuple[dict[str, Any], str, str | None]],
    key_lookup: KeyLookup,
    *,
    start_prev_hash: str = ZERO_HASH,
    start_seq: int = 1,
) -> ChainReport:
    """Verify envelopes, hashes, chain linkage, gaps and signatures.

    `rows` yields `(envelope_dict, signature_b64, stored_record_hash | None)`.
    The stored hash is compared when present (a DB export); a bare envelope
    stream just recomputes.
    """
    report = ChainReport(last_record_hash=start_prev_hash)
    expected_seq = start_seq
    for env_dict, signature, stored_hash in rows:
        seq = int(env_dict.get("seq", expected_seq))
        report.rows += 1
        try:
            env = LogEnvelope.model_validate(env_dict)
        except ValidationError as exc:
            report.findings.append(Finding(seq, Failure.ENVELOPE, str(exc.errors()[0]["msg"])))
            expected_seq = seq + 1
            continue
        if env.seq != expected_seq:
            report.findings.append(Finding(env.seq, Failure.GAP, f"expected seq {expected_seq}"))
        computed = env.record_hash()
        if stored_hash is not None and stored_hash != computed:
            report.findings.append(Finding(env.seq, Failure.HASH, "stored record_hash differs"))
        if env.prev_hash != report.last_record_hash:
            report.findings.append(Finding(env.seq, Failure.CHAIN, "prev_hash does not link"))
        key = key_lookup(env.key_id)
        if key is None:
            report.findings.append(Finding(env.seq, Failure.KEY, "unknown key_id"))
        elif env.ts < key.not_before or (key.revoked_at is not None and env.ts >= key.revoked_at):
            report.findings.append(Finding(env.seq, Failure.KEY, "key not active at ts"))
        elif not env.verify(key.public_key_b64, signature):
            report.findings.append(Finding(env.seq, Failure.SIGNATURE, "invalid signature"))
        elif key.compromise_suspected_from is not None and env.ts >= key.compromise_suspected_from:
            report.findings.append(Finding(env.seq, Failure.DISPUTED, "valid but inside compromise window"))
        report.last_record_hash = computed
        report.record_hashes.append(computed)
        expected_seq = env.seq + 1
    return report
