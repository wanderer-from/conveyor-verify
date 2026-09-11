# Security policy

conveyor-verify is the independent check on Conveyor publishers' integrity logs. A bug that makes it accept
a tampered export or bundle matters more than any other issue in this repository.

## Reporting

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/wanderer-from/conveyor-verify/security/advisories/new)
rather than public issues. Include the export or bundle that exhibits the problem when you can share it.
We aim to acknowledge within 72 hours.

## Scope

- False acceptance: an export or bundle that fails a check in the integrity specification but yields `"ok": true`.
- False rejection of valid material is a functional bug; report it as an ordinary issue.
- The vendored primitives are shared with the core; a finding there should be reported to
  [wanderer-from/conveyor](https://github.com/wanderer-from/conveyor) as well.
