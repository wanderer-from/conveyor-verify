# Contributing

Thanks for looking at the verifier. A few rules keep it trustworthy.

## Ground rules

- **No network.** The verifier must work on an air-gapped machine. Witness lookups (Rekor, OpenTimestamps)
  arrive later behind an explicit `--online` flag; offline stays the default.
- **Vendored primitives are not edited here.** `src/conveyor_verify/vendored/` mirrors
  `src/conveyor/integrity/` in the core repository byte for byte. Change the core, then run
  `scripts/sync-vendored.sh` there; the core's CI fails when the copies differ.
- **Every check has a negative test.** A new check comes with a test that tampers with the input and
  asserts the finding, see `tests/test_verify.py`.
- **Findings are sentences.** Report messages name the `seq` or file and what differed, so a reader can act
  on them without reading the code.

## Development

```bash
uv sync
uv run ruff check src tests
uv run mypy
uv run pytest -q
```

Python 3.12, `ruff` for style, `mypy --strict`. Commit messages describe the change in one line, English.

## Adding a publication root key

Publishers running Conveyor may add their root key attestation under `roots/` as
`<publication>-root-key.json` plus its minisign signature and public key; see `roots/README.md`.
