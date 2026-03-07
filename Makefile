.PHONY: lint test deploy verify check help

lint:                          ## Run all linters (yamllint + ansible-lint + syntax check)
	yamllint . && ansible-lint && ansible-playbook playbook.yml --syntax-check

test:                          ## Run molecule tests
	molecule test

deploy:                        ## Deploy to target server
	ansible-playbook playbook.yml -i inventory/hosts.yml --ask-vault-pass

verify:                        ## Run verification tasks only
	ansible-playbook playbook.yml -i inventory/hosts.yml --tags verify --ask-vault-pass

check: lint test               ## Run lint + test (full CI equivalent)

help:                          ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
