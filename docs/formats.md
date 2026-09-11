# File formats

All hashes are lowercase hex SHA-256. All JSON that is hashed or signed is canonicalized with JCS
(RFC 8785) and carries no floats and no nulls; see the
[integrity specification](https://github.com/wanderer-from/conveyor/blob/main/docs/spec/integrity.md).

## Log export (NDJSON)

`GET /integrity/v1/log?from=<seq>&limit=<n>` returns one JSON object per line, ascending `seq`:

```json
{"seq": 20, "envelope": {...}, "signature": "<base64 Ed25519>", "record_hash": "<hex>"}
```

`envelope` is the signed log envelope (`conveyor/v1/record` domain): `v`, `seq`, `ts`, `record_type`,
`subject_id`, `content_hash`, `prev_hash`, `key_id`, `payload` and, for some record types, `sources` or
`correction_of`. `record_hash` is redundant (it is recomputed) and present for convenience.

The verifier needs the export to start at `seq 1` or to be accompanied by `--keys` with the key chain
(`GET /integrity/v1/keys`), because signing keys are learned from `key_registered` rows.

## Anchor directory

The publisher writes one directory per anchored tree size:

```
anchors/
  17/
    root.txt
    log.ndjson          # incremental export since the previous anchor (hourly)
  18/
    root.txt
    log-full.ndjson     # full export (daily anchors)
```

`root.txt` has one `key value` pair per line: `tree_size`, `root`, `anchored_at`, and further metadata.
The verifier reads `tree_size` and `root`, rebuilds the Merkle root over the first `tree_size` record
hashes of the export, and reports the SHA-256 of any `log.ndjson` / `log-full.ndjson` found so it can be
compared with the object-storage version the publisher advertises in `public_refs`.

Object-storage anchors mirror this layout under `anchors/<size>/` in a bucket with versioning and a
retention lock; the bucket's version ids appear in the bundle's `anchors/public_refs.json`.

## Evidence bundle (zip)

`GET /integrity/v1/records/{slug}/proof` returns a zip:

```
manifest.json                 record slug, seq, tree size, generation time
event/canonical.json          canonical record form (what content_hash covers)
event/rendered.html           human-readable rendering (not verified)
event/content_hash.txt        hex hash of the canonical form
log/envelope.json             {"seq", "envelope", "signature", "record_hash"}
log/inclusion_proof.json      {"leaf_index", "tree_size", "leaf_hash", "path": [...], "root"} or {"pending": true}
anchors/root.txt              the covering anchor's root.txt
anchors/public_refs.json      where that root was anchored (bucket, version ids, witnesses)
anchors/proof.ots, timestamp.tsr, tsa_chain.pem   public witnesses, when present (phase B/C)
keys/key_chain.json           [{"id", "public_key", "not_before", "not_after", ...}]
methodology/                  methodology documents the record cites, with their own envelopes
sources/receipts.json         ingest receipts of the raw items behind the record
VERIFY.md                     these instructions in prose
SHA256SUMS                    digests of every file above
```

Files the verifier requires: `manifest.json`, `event/canonical.json`, `event/content_hash.txt`,
`log/envelope.json`, `log/inclusion_proof.json`, `keys/key_chain.json`, `SHA256SUMS`. The rest is
checked when present (`anchors/root.txt` must carry the proof root; `SHA256SUMS` must match every listed
file).
