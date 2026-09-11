.PHONY: test lint sign-root verify-root

test: ## Lint, type-check and test
	uv run ruff check src tests && uv run mypy && uv run pytest -q

sign-root: ## Sign the Brandmauer root key attestation with the operator minisign key
	minisign -Sm roots/brandmauer-root-key.json -s $${MINISIGN_KEY:-$$HOME/.minisign/minisign.key}

verify-root: ## Verify the attestation signature with the published operator key
	minisign -Vm roots/brandmauer-root-key.json -p roots/operator.minisign.pub
