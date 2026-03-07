## What

<!-- One sentence: what does this PR do? -->

## Why

<!-- What problem does it solve? -->

## Testing

- [ ] `make lint` passes (`yamllint .` + `ansible-lint` + syntax check)
- [ ] `make test` passes (`molecule test`)
- [ ] `ansible-playbook playbook.yml --check --diff` reviewed for unintended changes

## Deployment step affected

<!-- Which of the 14 steps does this change? (Step 1–14, Automated Deployment, or N/A) -->

## Security checklist

- [ ] No secrets or real IPs hardcoded
- [ ] No new sensitive API endpoints exposed
- [ ] Hardening not weakened
