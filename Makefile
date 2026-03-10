.PHONY: lint test role-tests deploy verify check caprover-check caprover-deploy caprover-verify scan help

lint:                          ## Run all linters (yamllint + ansible-lint + syntax check)
	yamllint . && ansible-lint && ansible-playbook playbook.yml --syntax-check && ansible-playbook caprover-playbook.yml --syntax-check

test:                          ## Run all Molecule tests (project, CapRover, and role-level)
	molecule test -s default && molecule test -s caprover && $(MAKE) role-tests

role-tests:                    ## Run Molecule tests for template-bearing roles
	cd roles/base && molecule test
	cd roles/openclaw-config && molecule test
	cd roles/openclaw-harden && molecule test
	cd roles/reverse-proxy && molecule test
	cd roles/maintenance && molecule test
	cd roles/monitoring && molecule test
	cd roles/convenience && molecule test

deploy:                        ## Deploy OpenClaw to target server
	ansible-playbook playbook.yml -i inventory/hosts.yml --ask-vault-pass

verify:                        ## Run verification tasks only
	ansible-playbook playbook.yml -i inventory/hosts.yml --tags verify --ask-vault-pass

caprover-deploy:               ## Deploy CapRover monitoring swarm (3 nodes)
	ansible-playbook caprover-playbook.yml -i inventory/caprover-hosts.yml --ask-vault-pass

caprover-verify:               ## Verify CapRover swarm deployment
	ansible-playbook caprover-playbook.yml -i inventory/caprover-hosts.yml --tags verify --ask-vault-pass

caprover-check:                ## Lint + test CapRover monitoring config only
	yamllint caprover-playbook.yml && ansible-lint caprover-playbook.yml && ansible-playbook caprover-playbook.yml --syntax-check && molecule test -s caprover

scan:                          ## Scan for secret leaks (requires gitleaks)
	gitleaks detect --source . -v

check: lint test scan          ## Run lint + test + scan (full CI equivalent)

help:                          ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
