# conveyor-verify

[![ci](https://github.com/wanderer-from/conveyor-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/wanderer-from/conveyor-verify/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Offline verifier for [Conveyor](https://github.com/wanderer-from/conveyor) integrity logs and evidence
bundles. It lets a reader check, on their own machine and without trusting the publisher's server, that

- a published record existed in the publication's integrity log at a given position,
- the log is an unbroken chain of Ed25519-signed envelopes with no gaps or rewrites,
- the Merkle roots the publisher anchored (locally, in object storage with retention lock, and later
  with public witnesses) really cover that log.

The first publication built on Conveyor is [Brandmauer Report](https://brandmauer.report); its root key
attestation lives in [`roots/`](roots/README.md).

## Install

```bash
uv tool install git+https://github.com/wanderer-from/conveyor-verify   # or: pipx install git+https://github.com/wanderer-from/conveyor-verify
conveyor-verify --help
```

From a checkout:

```bash
git clone https://github.com/wanderer-from/conveyor-verify && cd conveyor-verify
uv sync && uv run conveyor-verify --help
```

Python 3.12 or newer. Dependencies: `pydantic`, `pynacl` (Ed25519), `rfc8785` (JSON canonicalization).
The tool never opens a network connection.

## Quick start

Verify the evidence bundle of one record (the `Evidence` link on a record page, or
`GET https://integrity.<domain>/integrity/v1/records/<slug>/proof`):

```bash
conveyor-verify bundle 20260911-german-regulator-sets-conditions-evidence.zip
```

Verify a whole log export against the anchors the publisher wrote:

```bash
curl -s "https://integrity.brandmauer.report/integrity/v1/log?from=1&limit=10000" > log.ndjson
conveyor-verify log log.ndjson --anchors ./anchors
```

`./anchors` is a directory with one subdirectory per anchored tree size (`17/`, `18/`, ...), each holding
`root.txt` and the exported log at that size. Publishers ship these as the objects under `anchors/<size>/`
in their anchor bucket; see [docs/formats.md](docs/formats.md).

Both commands print a JSON report and exit with status `0` when every check passed, `1` otherwise.

## Commands

| Command | Input | Checks |
|---|---|---|
| `conveyor-verify log <export.ndjson> [--anchors DIR]... [--keys keys.json]` | NDJSON export from `/integrity/v1/log` or an anchor's `log.ndjson` | envelope hashes, chain linkage, signatures against the key history, Merkle root of every anchor directory, consistency proofs between consecutive anchors |
| `conveyor-verify bundle <evidence.zip>` | evidence bundle from `/integrity/v1/records/{slug}/proof` | file digests (`SHA256SUMS`), canonical record form hashes to `content_hash`, envelope carries it and recomputes its `record_hash`, signature against the bundled key chain, inclusion proof lands on the anchored root |

`--keys` supplies the key chain (`GET /integrity/v1/keys`) for a partial export that does not start at
`seq 1`; a full export carries its `key_registered` rows and needs nothing else.

## Reading the report

```json
{
  "ok": true,
  "rows": 21,
  "level": "operator-attested",
  "findings": [],
  "anchors": [
    {"dir": "anchors/20", "tree_size": 20, "root": "f927...fe37", "ok": true, "log.ndjson": "0634...23f"}
  ]
}
```

| Field | Meaning |
|---|---|
| `ok` | every check passed (`findings` contains only non-fatal notes) |
| `rows` | log rows examined (`1` for a bundle) |
| `level` | strongest assurance reached, see below |
| `findings` | human-readable problems; each fatal one sets `ok` to `false` |
| `anchors` | one entry per anchor directory (log mode) or the bundle's `public_refs` (bundle mode) |

### Assurance levels

| Level | Meaning |
|---|---|
| `unanchored` | the log verifies as a chain, but no anchor was supplied, so nothing pins its history in time |
| `preliminary` | bundle mode: the record is in the log, but no anchor covers it yet (anchors are written hourly) |
| `operator-attested` | the roots are anchored where only the publisher writes: local append-only directory and object storage with versioning and retention lock. Proves the publisher did not rewrite the log after anchoring, relying on the storage provider's retention guarantee |
| `independently witnessed` | at least one anchor carries a proof from a party the publisher does not control (Rekor, OpenTimestamps, RFC 3161 TSA). Not yet produced by v0 publishers; the verifier reports it as soon as `public_refs` carry such proofs |
| `failed` | a fatal finding; do not trust the export or bundle |

A `disputed` finding marks rows signed by a key inside a declared compromise window (`key_revoked` with
`compromised_from`): the signature is valid, but the publisher itself no longer vouches for it.

## What is verified, precisely

The checks implement section 7 of the Conveyor integrity specification
([docs/spec/integrity.md](https://github.com/wanderer-from/conveyor/blob/main/docs/spec/integrity.md)):

1. Every envelope is canonicalized with JCS (RFC 8785) and re-hashed under the domain prefix
   `conveyor/v1/record`; the result must equal the stored `record_hash`.
2. `prev_hash` of each row equals the `record_hash` of the previous row; `seq` increases by exactly one.
3. Ed25519 signatures (domain `conveyor/v1/sig`) verify against the key that was valid at that `seq`,
   with the key history rebuilt from `key_registered` and `key_revoked` rows.
4. For every anchor, the RFC 6962 Merkle root over the first `tree_size` record hashes equals `root.txt`,
   and consecutive anchors satisfy a consistency proof (the newer tree extends the older one).
5. In a bundle, the record's canonical form hashes (domain `conveyor/v1/rec`) to `event/content_hash.txt`,
   the envelope carries that hash, and the inclusion proof for the envelope's leaf verifies against the
   anchored root.

What it does not prove: that the content is true, that the publisher's server currently serves the same
log to everyone, or (at the `operator-attested` level) that the storage provider honoured retention.
[docs/threat-model.md](docs/threat-model.md) spells out the assumptions.

## Root of trust

Trust starts from the publisher's first system key. It is published in three places that should agree:
a `key_registered` row at `seq 1` of the log, a DNS TXT record `_conveyor-root-key.<domain>`, and a JSON
attestation under [`roots/`](roots/) in this repository signed with the operator's
[minisign](https://jedisct1.github.io/minisign/) key. Verify the attestation before trusting an export:

```bash
minisign -Vm roots/brandmauer-root-key.json -p roots/operator.minisign.pub
```

## Project layout

```
src/conveyor_verify/cli.py        command line
src/conveyor_verify/verify.py     log and bundle verification, report
src/conveyor_verify/vendored/     canonicalization, hashing, envelopes, Merkle, keys, chain
roots/                            root key attestations per publication
docs/                             formats and threat model
tests/                            end-to-end tests with a synthetic log and bundle
```

`vendored/` is a byte-identical copy of the core's `conveyor.integrity` package. The core repository's CI
fails when the two drift (`scripts/sync-vendored.sh` there), so this verifier and the writer always agree
on every byte that is hashed or signed.

## Development

```bash
uv sync
uv run ruff check src tests && uv run mypy && uv run pytest -q
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
