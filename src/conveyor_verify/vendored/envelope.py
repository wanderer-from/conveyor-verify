"""Signed content forms of integrity.md §3.

Every model is closed (extra fields rejected), contains no floats and never
serializes null: optional fields are omitted when absent. `canonical()` returns
the exact object that is canonicalized and hashed; changing any of these
models after the v1.0 freeze means a `conveyor/v2` domain.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from conveyor_verify.vendored.canon import Json
from conveyor_verify.vendored.hashing import ZERO_HASH, Domain, content_hash, record_hash
from conveyor_verify.vendored.keys import SigningKey, verify_record_hash

Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Uuid = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
]
Timestamp = Annotated[str, StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")]
Day = Annotated[str, StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}$")]
Decimal = Annotated[str, StringConstraints(pattern=r"^-?[0-9]+(\.[0-9]+)?$")]
MethodologyRef = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{1,63}/[0-9]+$")]
Lang = Annotated[str, StringConstraints(pattern=r"^[a-z]{2}(-[A-Z]{2})?$")]
Base64 = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9+/]+={0,2}$")]

_FLOAT_FORBIDDEN = "signed content must not contain floats"


class SignedModel(BaseModel):
    """Base for every signed form: closed, strict, null-free."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    @model_validator(mode="before")
    @classmethod
    def _no_floats_or_nulls(cls, data: Any) -> Any:
        # Input may be a dict (parsing) or an instance (copy); only dicts need checking.
        if isinstance(data, dict):  # pragma: no branch
            _reject_unsignable(data, "$")
        return data

    def canonical(self) -> dict[str, Any]:
        """The object that gets canonicalized: absent optionals omitted, never null."""
        result: dict[str, Any] = self.model_dump(mode="json", exclude_none=True)
        return result


def _reject_unsignable(value: Any, path: str) -> None:
    """Floats and explicit nulls never enter signed content (absent != null)."""
    if isinstance(value, float):
        raise ValueError(f"{path}: {_FLOAT_FORBIDDEN}")
    if value is None:
        raise ValueError(f"{path}: null is not allowed in signed content; omit the field")
    if isinstance(value, dict):
        for k, v in value.items():
            _reject_unsignable(v, f"{path}.{k}")
    elif isinstance(value, list | tuple):
        for i, v in enumerate(value):
            _reject_unsignable(v, f"{path}[{i}]")


class RecordType(StrEnum):
    """integrity_log.record_type catalog."""

    RECORD_PUBLISHED = "record_published"
    RECORD_SUPERSEDED = "record_superseded"
    RECORD_RETRACTED = "record_retracted"
    REGISTRY_CHANGE = "registry_change"
    CORRECTION_APPLIED = "correction_applied"
    DOCUMENT_PUBLISHED = "document_published"
    KEY_REGISTERED = "key_registered"
    KEY_REVOKED = "key_revoked"
    RECEIPTS_BATCH = "receipts_batch"
    CONSOLE_ACTION = "console_action"


# --- payloads per record_type (closed) -------------------------------------------------------


class RecordPublishedPayload(SignedModel):
    pipeline_version: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{1,63}/[0-9]+$")]


class RecordSupersededPayload(SignedModel):
    superseded_by: Uuid
    new_content_hash: Hex64
    reason: str
    reason_text: str


class RecordRetractedPayload(SignedModel):
    reason: str
    reason_text: str


class EmptyPayload(SignedModel):
    """`{}` for types without payload (registry_change)."""


class CorrectionAppliedPayload(SignedModel):
    sensitivity: Literal["normal", "sensitive"]
    provisional: bool


class DocumentPublishedPayload(SignedModel):
    kind: str
    name: str
    version: int = Field(ge=1)
    operator_sig: Base64 | None = None


class KeyRegisteredPayload(SignedModel):
    successor_of: Uuid | None = None


class KeyRevokedPayload(SignedModel):
    reason: str
    compromise_suspected_from: Timestamp | None = None


class ReceiptsBatchPayload(SignedModel):
    day: Day
    blocks: int = Field(ge=0)
    items: int = Field(ge=0)


class ConsoleActionPayload(SignedModel):
    process: str
    action: str


PAYLOAD_MODELS: dict[RecordType, type[SignedModel]] = {
    RecordType.RECORD_PUBLISHED: RecordPublishedPayload,
    RecordType.RECORD_SUPERSEDED: RecordSupersededPayload,
    RecordType.RECORD_RETRACTED: RecordRetractedPayload,
    RecordType.REGISTRY_CHANGE: EmptyPayload,
    RecordType.CORRECTION_APPLIED: CorrectionAppliedPayload,
    RecordType.DOCUMENT_PUBLISHED: DocumentPublishedPayload,
    RecordType.KEY_REGISTERED: KeyRegisteredPayload,
    RecordType.KEY_REVOKED: KeyRevokedPayload,
    RecordType.RECEIPTS_BATCH: ReceiptsBatchPayload,
    RecordType.CONSOLE_ACTION: ConsoleActionPayload,
}


# --- the log envelope -------------------------------------------------------------------------


class LogEnvelope(SignedModel):
    """integrity_log row content (integrity.md §3). `signature` is stored beside, not inside."""

    v: Literal[1] = 1
    seq: int = Field(ge=1)
    record_type: RecordType
    ts: Timestamp
    key_id: Uuid
    prev_hash: Hex64
    subject_id: Uuid
    content_hash: Hex64
    methodology_ref: MethodologyRef | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("record_type", mode="before")
    @classmethod
    def _coerce_record_type(cls, value: Any) -> Any:
        # strict mode does not coerce str -> enum; exports carry the plain string
        return RecordType(value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def _check(self) -> LogEnvelope:
        if self.seq == 1 and self.prev_hash != ZERO_HASH:
            raise ValueError("seq 1 must have prev_hash of 64 zeros")
        if self.seq > 1 and self.prev_hash == ZERO_HASH:
            raise ValueError("only seq 1 may have the zero prev_hash")
        PAYLOAD_MODELS[self.record_type].model_validate(self.payload)
        return self

    def record_hash(self) -> str:
        return record_hash(self.canonical())

    def sign(self, key: SigningKey) -> str:
        return key.sign(self.record_hash())

    def verify(self, public_key_b64: str, signature_b64: str) -> bool:
        return verify_record_hash(public_key_b64, self.record_hash(), signature_b64)


# --- content forms ----------------------------------------------------------------------------


class RecordForm(SignedModel):
    """Canonical record form, prefix conveyor/v1/rec (content_hash of records)."""

    v: Literal[1] = 1
    slug: str
    type: str
    title: str
    summary: str | None = None
    body: str | None = None
    lang: Lang
    occurred_at: Timestamp
    payload: dict[str, Any] = Field(default_factory=dict)
    methodology: MethodologyRef | None = None
    supersedes: str | None = None
    sources: list[Hex64] = Field(default_factory=list)

    @model_validator(mode="after")
    def _sources_sorted_unique(self) -> RecordForm:
        if self.sources != sorted(set(self.sources)):
            raise ValueError("sources must be unique content hashes sorted ascending")
        return self

    def content_hash(self) -> str:
        return content_hash(Domain.RECORD, self.canonical())


class ValueWrapper(SignedModel):
    """`{"value": ...}`; the empty wrapper `{}` means absent (never null)."""

    value: Json | None = None

    def canonical(self) -> dict[str, Any]:
        return {} if self.value is None else {"value": self.value}


class RegistryChangeForm(SignedModel):
    """Prefix conveyor/v1/rchange."""

    v: Literal[1] = 1
    entity: Uuid
    field: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$")]
    old: ValueWrapper
    new: ValueWrapper
    basis_type: Literal["record", "correction", "import", "manual"]
    basis_id: Uuid | None = None
    actor: str

    def canonical(self) -> dict[str, Any]:
        data = super().canonical()
        data["old"] = self.old.canonical()
        data["new"] = self.new.canonical()
        return data

    def content_hash(self) -> str:
        return content_hash(Domain.REGISTRY_CHANGE, self.canonical())


class Measurement(SignedModel):
    target: str
    result: str
    raw: dict[str, Any] = Field(default_factory=dict)


class ProbePacket(SignedModel):
    """Prefix conveyor/v1/probe, signed by the probe key."""

    v: Literal[1] = 1
    probe_key: Uuid
    counter: int = Field(ge=1)
    ts: Timestamp
    methodology: MethodologyRef
    measurements: list[Measurement] = Field(min_length=1)

    def content_hash(self) -> str:
        return content_hash(Domain.PROBE, self.canonical())


class IngestReceipt(SignedModel):
    """Prefix conveyor/v1/receipt, signed by the system key; leaves of hourly IN blocks."""

    v: Literal[1] = 1
    source: str
    external_id: str
    content_hash_: Hex64 = Field(alias="content_hash")
    received_at: Timestamp

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, populate_by_name=True)

    def canonical(self) -> dict[str, Any]:
        result: dict[str, Any] = self.model_dump(mode="json", exclude_none=True, by_alias=True)
        return result

    def receipt_hash(self) -> str:
        return content_hash(Domain.RECEIPT, self.canonical())


class KeyForm(SignedModel):
    """Prefix conveyor/v1/key: subject of key_registered / key_revoked rows."""

    v: Literal[1] = 1
    key_id: Uuid
    owner_type: Literal["probe", "system", "operator"]
    public_key: Base64
    algo: Literal["ed25519"] = "ed25519"
    not_before: Timestamp

    def content_hash(self) -> str:
        return content_hash(Domain.KEY, self.canonical())


class FieldChange(SignedModel):
    field: str
    old: ValueWrapper
    proposed: ValueWrapper

    def canonical(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "old": self.old.canonical(),
            "proposed": self.proposed.canonical(),
        }


class CorrectionForm(SignedModel):
    """Prefix conveyor/v1/correction: subject of correction_applied rows."""

    v: Literal[1] = 1
    correction_id: Uuid
    target_kind: Literal["record", "registry_record"]
    target_id: Uuid
    field_changes: list[FieldChange] = Field(min_length=1)
    sensitivity: Literal["normal", "sensitive"]
    provisional: bool
    source_url: str | None = None

    def canonical(self) -> dict[str, Any]:
        data = super().canonical()
        data["field_changes"] = [fc.canonical() for fc in self.field_changes]
        return data

    def content_hash(self) -> str:
        return content_hash(Domain.CORRECTION, self.canonical())


class ConsoleActionForm(SignedModel):
    """Prefix conveyor/v1/action: subject of console_action rows (sensitive actions only)."""

    v: Literal[1] = 1
    action_id: Uuid
    task_id: Uuid
    actor_hash: Hex64
    process: str
    action: str
    input: dict[str, Any] = Field(default_factory=dict)
    ts: Timestamp

    def content_hash(self) -> str:
        return content_hash(Domain.ACTION, self.canonical())


class BlockForm(SignedModel):
    """Prefix conveyor/v1/block: hourly IN block header; block_hash chains blocks (integrity.md §5)."""

    v: Literal[1] = 1
    seq: int = Field(ge=1)
    period_start: Timestamp
    period_end: Timestamp
    items_count: int = Field(ge=0)
    merkle_root: Hex64
    prev_block_hash: Hex64

    def block_hash(self) -> str:
        return content_hash(Domain.BLOCK, self.canonical())


def document_content_hash(content: Json) -> str:
    """content_hash of a document version: sha256 over conveyor/v1/doc + JCS(content)."""
    return content_hash(Domain.DOCUMENT, content)


_METHODOLOGY_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}/[0-9]+$")


def is_methodology_ref(value: str) -> bool:
    return bool(_METHODOLOGY_RE.match(value))
