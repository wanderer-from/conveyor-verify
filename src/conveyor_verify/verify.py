"""Verification steps of integrity.md §7, fully offline.

`verify_log(lines, anchors)`: envelope hashes, chain, signatures against the
key history rebuilt from the export itself, tree roots per anchor, consistency
between anchored sizes, bundle hashes of local anchor directories.
`verify_bundle(zip)`: an evidence bundle (api.md layout).
"""

from __future__ import annotations

import hashlib
import io
import itertools
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from conveyor_verify.vendored.chain import KeyRecord, keys_from_log, verify_chain
from conveyor_verify.vendored.envelope import LogEnvelope, RecordForm
from conveyor_verify.vendored.hashing import hex_to_bytes
from conveyor_verify.vendored.merkle import leaf_hash, root_hash, verify_consistency, verify_inclusion


@dataclass
class Report:
    ok: bool = True
    rows: int = 0
    findings: list[str] = field(default_factory=list)
    anchors: list[dict[str, Any]] = field(default_factory=list)
    level: str = "unverified"

    def fail(self, message: str) -> None:
        self.ok = False
        self.findings.append(message)

    def to_json(self) -> str:
        return json.dumps(
            {
                "ok": self.ok,
                "rows": self.rows,
                "level": self.level,
                "findings": self.findings,
                "anchors": self.anchors,
            },
            indent=2,
        )


def parse_ndjson(data: bytes) -> list[dict[str, Any]]:
    return [json.loads(line) for line in data.decode().splitlines() if line.strip()]


def key_lookup(
    lines: list[dict[str, Any]], extra_keys: list[dict[str, Any]] | None = None
) -> dict[str, KeyRecord]:
    keys = keys_from_log(
        [
            (
                line["envelope"]
                | {
                    "payload": {
                        **line["envelope"].get("payload", {}),
                        **({"public_key": line["public_key"]} if "public_key" in line else {}),
                    }
                },
                line["signature"],
            )
            for line in lines
        ]
    )
    for k in extra_keys or []:
        if k.get("id") and k.get("public_key") and k["id"] not in keys:
            keys[k["id"]] = KeyRecord(
                k["id"],
                k["public_key"],
                k.get("not_before") or "1970-01-01T00:00:00Z",
                k.get("revoked_at"),
                k.get("compromise_suspected_from"),
            )
    return keys


def verify_log(
    lines: list[dict[str, Any]],
    anchor_dirs: list[Path] | None = None,
    extra_keys: list[dict[str, Any]] | None = None,
) -> Report:
    report = Report(rows=len(lines))
    keys = key_lookup(lines, extra_keys)
    if not keys:
        report.fail("no key_registered row with public_key in the export; cannot verify signatures")
    chain = verify_chain(
        [(line["envelope"], line["signature"], line.get("record_hash")) for line in lines], keys.get
    )
    for finding in chain.findings:
        (report.findings.append if finding.category.value == "disputed" else report.fail)(
            f"seq {finding.seq}: {finding.category.value}: {finding.detail}"
        )
    leaves = [hex_to_bytes(h) for h in chain.record_hashes]
    sizes: list[tuple[int, bytes]] = []
    for directory in anchor_dirs or []:
        for bundle in sorted(p for p in Path(directory).iterdir() if p.is_dir() and p.name.isdigit()):
            root_txt = (bundle / "root.txt").read_text()
            fields = dict(line.split(" ", 1) for line in root_txt.splitlines() if " " in line)
            size, root = int(fields["tree_size"]), fields["root"]
            entry: dict[str, Any] = {"dir": str(bundle), "tree_size": size, "root": root, "ok": True}
            if size > len(leaves):
                entry["ok"] = False
                report.fail(f"anchor {bundle.name}: tree_size {size} exceeds the export ({len(leaves)} rows)")
            elif root_hash(leaves[:size]).hex() != root:
                entry["ok"] = False
                report.fail(f"anchor {bundle.name}: rebuilt root differs from root.txt")
            for name in ("log.ndjson", "log-full.ndjson"):
                path = bundle / name
                if path.exists():
                    entry[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            report.anchors.append(entry)
            if entry["ok"]:
                sizes.append((size, hex_to_bytes(root)))
    for (a, ra), (b, rb) in itertools.pairwise(sizes):
        from conveyor_verify.vendored.merkle import consistency_proof

        if not verify_consistency(a, b, consistency_proof(leaves[:b], a, b), ra, rb):
            report.fail(f"anchors {a} -> {b}: consistency proof failed")
    report.level = (
        "operator-attested" if report.anchors and report.ok else ("unanchored" if report.ok else "failed")
    )
    return report


def verify_bundle(data: bytes) -> Report:
    report = Report()
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        report.fail("not a zip file")
        return report
    names = set(zf.namelist())
    for required in (
        "manifest.json",
        "event/canonical.json",
        "event/content_hash.txt",
        "log/envelope.json",
        "log/inclusion_proof.json",
        "keys/key_chain.json",
        "SHA256SUMS",
    ):
        if required not in names:
            report.fail(f"missing {required}")
    if not report.ok:
        return report
    for line in zf.read("SHA256SUMS").decode().splitlines():
        digest, _, name = line.partition("  ")
        if name in names and hashlib.sha256(zf.read(name)).hexdigest() != digest:
            report.fail(f"SHA256SUMS mismatch for {name}")
    canonical = json.loads(zf.read("event/canonical.json"))
    content_hash = zf.read("event/content_hash.txt").decode().strip()
    try:
        if RecordForm.model_validate(canonical).content_hash() != content_hash:
            report.fail("event/canonical.json does not hash to event/content_hash.txt")
    except ValueError as exc:
        report.fail(f"event/canonical.json is not a valid record form: {exc}")
    row = json.loads(zf.read("log/envelope.json"))
    env = LogEnvelope.model_validate(row["envelope"])
    if env.content_hash != content_hash:
        report.fail("log envelope content_hash differs from the event content hash")
    if row.get("record_hash") and env.record_hash() != row["record_hash"]:
        report.fail("envelope record_hash does not recompute")
    keys = {k["id"]: k for k in json.loads(zf.read("keys/key_chain.json"))}
    key = keys.get(env.key_id)
    if key is None:
        report.fail(f"signing key {env.key_id} not in keys/key_chain.json")
    elif not env.verify(key["public_key"], row["signature"]):
        report.fail("envelope signature invalid")
    proof = json.loads(zf.read("log/inclusion_proof.json"))
    if proof.get("pending"):
        report.findings.append("preliminary bundle: no covering anchor yet")
        report.level = "preliminary"
    else:
        leaf = leaf_hash(hex_to_bytes(env.record_hash()))
        if proof.get("leaf_hash") != leaf.hex():
            report.fail("inclusion proof leaf hash differs from the envelope")
        if not verify_inclusion(
            leaf,
            int(proof["leaf_index"]),
            int(proof["tree_size"]),
            [hex_to_bytes(p) for p in proof["path"]],
            hex_to_bytes(proof["root"]),
        ):
            report.fail("inclusion proof does not verify against the anchored root")
        if (
            "anchors/root.txt" in names
            and f"root {proof['root']}" not in zf.read("anchors/root.txt").decode()
        ):
            report.fail("anchors/root.txt does not carry the proof root")
        anchors = (
            json.loads(zf.read("anchors/public_refs.json")) if "anchors/public_refs.json" in names else []
        )
        report.anchors = anchors
        witnessed = any(a.get("level") == "independently witnessed" for a in anchors)
        report.level = (
            ("independently witnessed" if witnessed else "operator-attested") if report.ok else "failed"
        )
    report.rows = 1
    return report
