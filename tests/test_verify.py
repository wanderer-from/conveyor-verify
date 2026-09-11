"""End-to-end: build a small signed log in memory, anchor it to a directory, verify; then corrupt it."""

import hashlib
import io
import json
import uuid
import zipfile
from pathlib import Path

from conveyor_verify.cli import main
from conveyor_verify.vendored.envelope import KeyForm, LogEnvelope, RecordForm
from conveyor_verify.vendored.hashing import ZERO_HASH, hex_to_bytes
from conveyor_verify.vendored.keys import SigningKey
from conveyor_verify.vendored.merkle import inclusion_proof, leaf_hash, root_hash
from conveyor_verify.verify import parse_ndjson, verify_bundle, verify_log

KEY = SigningKey.generate()
KEY_ID = str(uuid.uuid4())


def build_log(n: int) -> list[dict]:  # type: ignore[type-arg]
    lines = []
    prev = ZERO_HASH
    for seq in range(1, n + 1):
        if seq == 1:
            rt, subject, ch, payload = (
                "key_registered",
                KEY_ID,
                KeyForm(
                    key_id=KEY_ID,
                    owner_type="system",
                    public_key=KEY.public_key_b64,
                    not_before="2026-09-11T00:00:00Z",
                ).content_hash(),
                {},
            )
        else:
            rt, subject, ch, payload = "registry_change", str(uuid.uuid4()), f"{seq:064x}", {}
        env = LogEnvelope.model_validate(
            {
                "seq": seq,
                "record_type": rt,
                "ts": f"2026-09-11T10:{seq:02d}:00Z",
                "key_id": KEY_ID,
                "prev_hash": prev,
                "subject_id": subject,
                "content_hash": ch,
                "payload": payload,
            }
        )
        line = {"envelope": env.canonical(), "signature": env.sign(KEY), "record_hash": env.record_hash()}
        if seq == 1:
            line["public_key"] = KEY.public_key_b64
        lines.append(line)
        prev = env.record_hash()
    return lines


def write_anchor(root_dir: Path, lines: list[dict], size: int) -> None:  # type: ignore[type-arg]
    leaves = [hex_to_bytes(line["record_hash"]) for line in lines[:size]]
    d = root_dir / str(size)
    d.mkdir(parents=True)
    (d / "root.txt").write_text(
        f"tree_size {size}\nroot {root_hash(leaves).hex()}\nts 2026-09-11T11:00:00Z\n"
    )
    (d / "log.ndjson").write_text("".join(json.dumps(line) + "\n" for line in lines[:size]))


def test_valid_log_with_two_anchors(tmp_path: Path) -> None:
    lines = build_log(6)
    write_anchor(tmp_path / "anchors", lines, 4)
    write_anchor(tmp_path / "anchors", lines, 6)
    report = verify_log(lines, [tmp_path / "anchors"])
    assert report.ok, report.findings
    assert report.rows == 6
    assert report.level == "operator-attested"
    assert [a["tree_size"] for a in report.anchors] == [4, 6]
    export = tmp_path / "log.ndjson"
    export.write_text("".join(json.dumps(line) + "\n" for line in lines))
    assert main(["log", str(export), "--anchors", str(tmp_path / "anchors")]) == 0


def test_tampering_is_detected(tmp_path: Path) -> None:
    lines = build_log(5)
    write_anchor(tmp_path / "anchors", lines, 5)
    tampered = json.loads(json.dumps(lines))
    tampered[2]["envelope"]["content_hash"] = "ff" * 32
    report = verify_log(tampered, [tmp_path / "anchors"])
    assert not report.ok
    assert any("seq 3: hash" in f for f in report.findings)
    assert any("seq 3: signature" in f for f in report.findings)
    assert any("seq 4: chain" in f for f in report.findings)
    assert any("rebuilt root differs" in f for f in report.findings)
    # gap
    report2 = verify_log([lines[0], lines[1], lines[3]], [])
    assert any("gap" in f for f in report2.findings)
    # no key material at all
    no_key = [dict(line) for line in lines]
    no_key[0].pop("public_key")
    report3 = verify_log(no_key, [])
    assert any("no key_registered" in f for f in report3.findings)
    # oversize anchor
    write_anchor(tmp_path / "big", lines, 5)
    report4 = verify_log(lines[:3], [tmp_path / "big"])
    assert any("exceeds the export" in f for f in report4.findings)
    assert parse_ndjson(b"\n") == []


def make_bundle(
    lines: list[dict], seq: int, *, break_proof: bool = False, preliminary: bool = False
) -> bytes:  # type: ignore[type-arg]
    leaves = [hex_to_bytes(line["record_hash"]) for line in lines]
    form = RecordForm(slug="s", type="t", title="T", lang="en", occurred_at="2026-09-11T10:00:00Z")
    env = LogEnvelope.model_validate(
        {
            **lines[seq - 1]["envelope"],
            "record_type": "record_published",
            "content_hash": form.content_hash(),
            "payload": {"pipeline_version": "news-digest/1"},
        }
    )
    row = {"envelope": env.canonical(), "signature": env.sign(KEY), "record_hash": env.record_hash()}
    leaves[seq - 1] = hex_to_bytes(env.record_hash())
    proof = (
        {"pending": True}
        if preliminary
        else {
            "leaf_index": seq - 1,
            "tree_size": len(leaves),
            "leaf_hash": leaf_hash(leaves[seq - 1]).hex(),
            "path": [p.hex() for p in inclusion_proof(leaves, seq - 1)],
            "root": root_hash(leaves).hex(),
        }
    )
    if break_proof and not preliminary:
        proof["path"] = proof["path"][:-1]
    files = {
        "manifest.json": json.dumps({"slug": "s", "seq": seq, "preliminary": preliminary}).encode(),
        "event/canonical.json": json.dumps(form.canonical()).encode(),
        "event/content_hash.txt": (form.content_hash() + "\n").encode(),
        "log/envelope.json": json.dumps(row).encode(),
        "log/inclusion_proof.json": json.dumps(proof).encode(),
        "anchors/root.txt": (f"tree_size {len(leaves)}\nroot {root_hash(leaves).hex()}\n").encode(),
        "anchors/public_refs.json": json.dumps([{"level": "operator-attested"}]).encode(),
        "keys/key_chain.json": json.dumps([{"id": KEY_ID, "public_key": KEY.public_key_b64}]).encode(),
        "VERIFY.md": b"see README",
    }
    files["SHA256SUMS"] = "".join(
        f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in sorted(files.items())
    ).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_bundle_verification(tmp_path: Path) -> None:
    lines = build_log(4)
    good = make_bundle(lines, 3)
    report = verify_bundle(good)
    assert report.ok, report.findings
    assert report.level == "operator-attested"
    path = tmp_path / "b.zip"
    path.write_bytes(good)
    assert main(["bundle", str(path)]) == 0
    broken = verify_bundle(make_bundle(lines, 3, break_proof=True))
    assert not broken.ok
    assert any("inclusion proof" in f for f in broken.findings)
    prelim = verify_bundle(make_bundle(lines, 3, preliminary=True))
    assert prelim.ok
    assert prelim.level == "preliminary"
    assert not verify_bundle(b"nope").ok
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("manifest.json", "{}")
    missing = verify_bundle(buf.getvalue())
    assert any("missing" in f for f in missing.findings)
    assert "SHA256SUMS" in names
