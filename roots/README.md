# Root key attestations

Each file `<publication>-root-key.json` states the first system key of a Conveyor publication:

```json
{"key_id": "<uuid>", "public_key": "<base64 Ed25519>", "algo": "ed25519"}
```

It must agree with the `key_registered` row at `seq 1` of that publication's log and with the DNS TXT
record `_conveyor-root-key.<domain>`. The operator signs the file with minisign; the signature
(`.minisig`) and the operator's public key sit next to it.

## Brandmauer Report

| | |
|---|---|
| domain | brandmauer.report |
| integrity API | https://integrity.brandmauer.report/integrity/v1/ |
| key id | `2a01e470-c79b-413f-af2d-ff039790625c` |
| attestation | [brandmauer-root-key.json](brandmauer-root-key.json) |
| operator key | [operator.minisign.pub](operator.minisign.pub) |

Verify the attestation:

```bash
minisign -Vm roots/brandmauer-root-key.json -p roots/operator.minisign.pub
```

Then compare `public_key` with the `seq 1` row of the log:

```bash
curl -s "https://integrity.brandmauer.report/integrity/v1/log?from=1&limit=1" | python3 -c "import sys,json; e=json.loads(sys.stdin.readline())['envelope']; print(e['record_type'], e['payload'].get('public_key'))"
```

Status: the attestation is present; its minisign signature is added by the operator before launch
(stage 7 of the Conveyor plan), together with the DNS TXT record.

## Operator procedure

```bash
make sign-root        # minisign -Sm roots/brandmauer-root-key.json -s ~/.minisign/minisign.key
make verify-root      # checks the signature with roots/operator.minisign.pub
```
