# conveyor-verify

Offline verifier for [Conveyor](https://github.com/wanderer-from/conveyor) integrity logs and evidence bundles.
Everything a reader needs to check that a published record existed at a given point in the log, that the log
is an unbroken signed chain, and that the Merkle roots were anchored, without trusting the publisher's server.

```bash
uv tool install conveyor-verify            # or: pipx install conveyor-verify
conveyor-verify bundle 20260910-outage-evidence.zip
conveyor-verify log log-full.ndjson --anchors /path/to/anchors
```

What is checked (integrity.md §7 of the Conveyor specification):

1. every envelope re-hashes to its `record_hash` (`conveyor/v1/record` domain);
2. the chain: `prev_hash` linkage, no `seq` gaps;
3. Ed25519 signatures against the key history rebuilt from `key_registered` / `key_revoked` rows
   (compromise windows are reported as *disputed*);
4. Merkle roots for every anchored tree size (RFC 6962) and consistency proofs between them;
5. anchor bundles: `root.txt` and export hashes; object-storage version ids and public witnesses
   (Rekor, OpenTimestamps, TSA) are reported per period as the achieved level:
   `operator-attested` or `independently witnessed`;
6. bundle mode: the record's canonical form hashes to `event/content_hash.txt`, the envelope carries it,
   the inclusion proof lands on the anchored root.

Root of trust: the first system key, published in DNS TXT `_conveyor-root-key.<domain>` and in this
repository under `roots/`, signed with the operator's minisign key.

The cryptographic primitives under `src/conveyor_verify/vendored/` are a byte-identical copy of the core's
`conveyor.integrity` package; the core repository's CI fails when they drift.
