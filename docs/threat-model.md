# Threat model

## Goal

A reader who holds an export or a bundle, the publisher's root key attestation and this tool can decide
whether the publisher's integrity log was rewritten after publication, without trusting the publisher's
server at the time of checking.

## Assumptions

- SHA-256 and Ed25519 are secure.
- The reader obtained the root key through a channel the publisher's server does not control: the signed
  attestation in this repository, the DNS TXT record, or both.
- The reader's copy of this tool is authentic (clone over HTTPS, check the commit, or review the sources;
  the verifier is small on purpose).

## What a passing verification proves

- **Chain integrity**: every row is hashed under a fixed domain prefix and linked to its predecessor; any
  insertion, deletion or edit changes every later `record_hash` and breaks a signature.
- **Authorship**: every row is signed by a key that the log itself registered, starting from the root key.
- **Anchoring**: the Merkle root over the first `tree_size` rows equals what the publisher anchored. If the
  anchor was written to a medium the publisher cannot alter afterwards, the log up to that size is fixed
  from that moment.
- **Inclusion** (bundle): the record's canonical content is exactly what the log row commits to, and that
  row is under an anchored root.

## What it does not prove

- **Truth of content.** The log commits to what was published, not to whether it is correct. Corrections
  and retractions are themselves log rows.
- **Equivocation at the operator-attested level.** A publisher who controls both the log and the storage
  bucket could, in theory, maintain two histories if the storage provider's retention lock fails. The
  `operator-attested` level relies on that lock; the `independently witnessed` level (Rekor, OpenTimestamps,
  RFC 3161) removes this reliance and is reported automatically once the publisher produces such proofs.
- **Freshness.** An old but valid export is still valid; check `anchored_at` and the latest tree size
  against `GET /integrity/v1/status` if recency matters.
- **Key compromise outside declared windows.** Rows signed inside a declared compromise window are marked
  `disputed`; undeclared compromise is indistinguishable from legitimate signing, as with any signature
  scheme.

## Vendored primitives

The hashing, canonicalization, envelope, Merkle and chain code is copied byte for byte from the core's
`conveyor.integrity` package rather than imported, so that this tool has no dependency on the core and
cannot be steered by a compromised core release. The core's CI enforces that the copies match.
