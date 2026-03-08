.PHONY: lint test deploy verify check caprover-deploy caprover-verify help

lint:                          ## Run all linters (yamllint + ansible-lint + syntax check)
	yamllint . && ansible-lint && ansible-playbook playbook.yml --syntax-check && ansible-playbook caprover-playbook.yml --syntax-check

test:                          ## Run molecule tests
	molecule test

deploy:                        ## Deploy OpenClaw to target server
	ansible-playbook playbook.yml -i inventory/hosts.yml --ask-vault-pass

verify:                        ## Run verification tasks only
	ansible-playbook playbook.yml -i inventory/hosts.yml --tags verify --ask-vault-pass

caprover-deploy:               ## Deploy CapRover monitoring swarm (3 nodes)
	ansible-playbook caprover-playbook.yml -i inventory/caprover-hosts.yml --ask-vault-pass

caprover-verify:               ## Verify CapRover swarm deployment
	ansible-playbook caprover-playbook.yml -i inventory/caprover-hosts.yml --tags verify --ask-vault-pass

check: lint test               ## Run lint + test (full CI equivalent)

help:                          ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
