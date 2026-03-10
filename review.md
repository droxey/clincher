# Review Summary

Generated on 2026-03-09 for `droxey/clincher`.

## Code-reviewing agents found in this repository

There is **one distinct code-reviewing agent** in this repository, exposed through **two repo artifacts**:

1. **Portable prompt:** `prompts/ansible-review.prompt.md`
   - Purpose: production-grade Ansible code review for playbooks, roles, and task files
   - Focus: FQCN usage, idempotency, security, handlers, check-mode safety, and testability
   - Intended scope: Ansible only; not for Terraform, Docker-only repos, or general non-Ansible code review

2. **Claude command wrapper:** `.claude/commands/ansible-review.md`
   - Purpose: Claude-specific wrapper around the same Ansible review logic
   - Focus: same review criteria as the portable prompt
   - Difference from the prompt: adds Claude metadata such as version and allowed tools

## Existing repository validation run before review

These repo-native checks were run before compiling the review:

- `make lint` ✅
- `make test` ✅

Notes:

- Initial runs failed only because the sandbox was missing the repo's declared tooling (`ansible-lint`, `molecule`); after installing `requirements.txt` and `requirements.yml`, the project checks passed.
- `make lint` completed successfully.
- `make test` completed successfully, including project-level and role-level Molecule scenarios.

---

## Review run 1 — portable prompt

Source instructions: `prompts/ansible-review.prompt.md`

### Verdict

- FAIL

### Critical issues

- Severity: blocker
- File / path: `inventory/caprover-hosts.yml`
- Task / handler / section: Inventory host definitions
- Rule or principle violated: Security / portability — no hardcoded real infrastructure IPs in committed inventory
- Evidence:
  ```yaml
  11.           ansible_host: 192.3.81.8
  17.           ansible_host: 107.174.51.158
  20.           ansible_host: 198.23.228.15
  ```
- Why it matters: This leaks live infrastructure details, makes the repo non-portable, and violates the repo’s own placeholder pattern used elsewhere (`YOUR_SERVER_IP`, `YOUR_OPENCLAW_SERVER_IP`).
- Minimal fix: Replace committed IPs with placeholders/example values and keep real inventory out of git.
- Corrected snippet or patch:
  ```yaml
  all:
    children:
      caprover_leader:
        hosts:
          caprover-ny:
            ansible_host: YOUR_CAPROVER_LEADER_IP
            caprover_role: leader
      caprover_workers:
        hosts:
          caprover-la:
            ansible_host: YOUR_CAPROVER_WORKER1_IP
            caprover_role: worker
          caprover-chi:
            ansible_host: YOUR_CAPROVER_WORKER2_IP
            caprover_role: worker
  ```

- Severity: blocker
- File / path: `group_vars/caprover/vars.yml`
- Task / handler / section: CapRover defaults
- Rule or principle violated: Security — secrets must not be stored as plaintext defaults; use Vault
- Evidence:
  ```yaml
  17. caprover_initial_password: captain42
  ```
- Why it matters: This is a predictable bootstrap credential committed in plaintext and then used for authenticated API calls in `roles/caprover-swarm/tasks/main.yml`. If not overridden correctly, the deployment starts from a known password.
- Minimal fix: Remove the real default, move it to vaulted vars, and assert it is set before use.
- Corrected snippet or patch:
  ```yaml
  # group_vars/caprover/vars.yml
  caprover_initial_password: ""
  ```
  ```yaml
  # caprover-playbook.yml pre_tasks
  - name: Validate CapRover bootstrap secret
    ansible.builtin.assert:
      that:
        - caprover_initial_password is defined
        - caprover_initial_password | length > 0
        - caprover_initial_password != 'captain42'
      fail_msg: "caprover_initial_password must be set in vault"
  ```

- Severity: high
- File / path: `roles/caprover-swarm/tasks/main.yml`, `group_vars/caprover/vars.yml`
- Task / handler / section: CapRover bootstrap API calls; firewall port list
- Rule or principle violated: Security — do not send passwords/tokens over plaintext HTTP on a publicly exposed admin port
- Evidence:
  ```yaml
  104.         url: "http://{{ ansible_host }}:3000/api/v2/user/system/info"
  107.           x-captain-password: "{{ caprover_initial_password }}"
  127.         url: "http://{{ ansible_host }}:3000/api/v2/user/changepassword"
  147.         url: "http://{{ ansible_host }}:3000/api/v2/login"
  163.         url: "http://{{ ansible_host }}:3000/api/v2/user/system/changerootdomain"
  175.         url: "http://{{ ansible_host }}:3000/api/v2/user/system/enablessl"
  188.         url: "http://{{ ansible_host }}:3000/api/v2/user/system/forcessl"
  ```
  ```yaml
  42.   - { port: 3000, proto: tcp, comment: "CapRover UI (initial setup)" }
  ```
- Why it matters: The playbook sends the bootstrap password and later auth token over HTTP to port 3000, while the firewall configuration allows that port broadly. That is a credential exposure risk during initial setup.
- Minimal fix: Do not expose 3000 publicly; restrict it to the admin IP (or localhost/SSH tunnel) during bootstrap and remove it after TLS is enabled.
- Corrected snippet or patch:
  ```yaml
  # group_vars/caprover/vars.yml
  caprover_ufw_allowed_ports:
    - { port: 80, proto: tcp, comment: "HTTP" }
    - { port: 443, proto: tcp, comment: "HTTPS" }
    - { port: 996, proto: tcp, comment: "CapRover registry" }
    - { port: 7946, proto: any, comment: "Docker Swarm node discovery" }
    - { port: 4789, proto: udp, comment: "Docker overlay network" }
    - { port: 2377, proto: tcp, comment: "Docker Swarm management" }
  ```
  ```yaml
  - name: Allow CapRover bootstrap UI only from admin IP
    community.general.ufw:
      rule: allow
      from_ip: "{{ caprover_admin_ip }}"
      to_port: "3000"
      proto: tcp
  ```

- Severity: high
- File / path: `roles/caprover-swarm/tasks/main.yml`
- Task / handler / section: `Deploy CapRover captain`
- Rule or principle violated: Idempotency / determinism — existence check must match the object actually created
- Evidence:
  ```yaml
  81.     - name: Check if CapRover is running
  83.         cmd: docker service ls --filter name=captain-captain --format '{{ .Name }}'
  ...
  87.     - name: Deploy CapRover via Docker
  90.           docker run -d
  91.           --name captain-captain
  ```
- Why it matters: The task checks for a Swarm service, but creates a standalone container. On rerun, the service check stays empty and the play tries to create `captain-captain` again, which is not idempotent and can fail immediately.
- Minimal fix: Manage the same object you check for, preferably with `community.docker.docker_container`.
- Corrected snippet or patch:
  ```yaml
  - name: Deploy CapRover via Docker
    community.docker.docker_container:
      name: captain-captain
      image: "caprover/caprover:{{ caprover_version }}"
      restart_policy: unless-stopped
      env:
        ACCEPTED_TERMS: "true"
        MAIN_NODE_IP_ADDRESS: "{{ ansible_host }}"
      published_ports:
        - "80:80"
        - "443:443"
        - "3000:3000"
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock
        - /captain:/captain
      state: started
  ```

- Severity: high
- File / path: `roles/openclaw-harden/tasks/main.yml`, `roles/openclaw-integrate/tasks/main.yml`
- Task / handler / section: Gateway auth/token config; integration secret install
- Rule or principle violated: Correct Ansible usage / security — avoid shell-style command construction with templated data
- Evidence:
  ```yaml
  62. docker exec openclaw sh -c 'openclaw config set gateway.auth.token "$(cat /tmp/.gw-token)"'
  79. ansible.builtin.command: "docker exec openclaw openclaw config set {{ item.key }} {{ item.value }}"
  ```
  ```yaml
  37. docker exec openclaw sh -c
  38. 'cat /tmp/.voyage-env > /root/.openclaw/.env && chmod 600 /root/.openclaw/.env && rm -f /tmp/.voyage-env'
  74. docker exec openclaw sh -c
  75. 'openclaw config set channels.telegram.token "$(cat /tmp/.tg-token)" && rm -f /tmp/.tg-token'
  ```
- Why it matters: These tasks rely on shell parsing, nested quoting, and templated string interpolation. That is brittle, hard to audit, and not check/diff safe; templated values can also split unexpectedly.
- Minimal fix: Use `argv` form for `ansible.builtin.command` and read token/file content outside the shell (`slurp`/lookup) before passing it as an argument.
- Corrected snippet or patch:
  ```yaml
  - name: Read gateway token from host file
    ansible.builtin.slurp:
      src: "{{ openclaw_base_dir }}/monitoring/.gateway-token"
    register: gateway_token_file
    no_log: true

  - name: Apply gateway auth token
    ansible.builtin.command:
      argv:
        - docker
        - exec
        - openclaw
        - openclaw
        - config
        - set
        - gateway.auth.token
        - "{{ gateway_token_file.content | b64decode | trim }}"
    no_log: true
  ```

### Remaining findings

#### Definite rule violations

- `roles/openclaw-harden/tasks/main.yml:208-211` runs `openclaw security audit --deep --fix` during normal converge and forces `changed_when: false`. That is a mutating “auto-fix” action without an explicit safeguard/tag and without truthful change reporting.
- All local roles are missing `meta/main.yml`, so supported platforms, minimum Ansible version, and role dependencies are undocumented.
- Several token-bearing CapRover API calls are not consistently protected with `no_log: true`, e.g. `roles/caprover-swarm/tasks/main.yml:161-195` and `roles/caprover-apps/tasks/main.yml:407-417`.

#### Likely bugs / idempotency risks

- Mutating `openclaw config set` tasks in `roles/openclaw-harden/tasks/main.yml` and `roles/openclaw-integrate/tasks/main.yml` are broadly marked `changed_when: false`, so reruns cannot distinguish no-op from actual change.
- `roles/openclaw-integrate/tasks/main.yml:35-38` overwrites `/root/.openclaw/.env` with `cat /tmp/.voyage-env > /root/.openclaw/.env`; whether that destroys other required env entries needs repo/runtime context.
- `roles/reverse-proxy/tasks/main.yml:95-101` runs `tailscale serve --bg ...` with no idempotent pre-check and `changed_when: false`, so `--check` and re-runs are not trustworthy.

#### Security risks

- `caprover-playbook.yml:20` and `inventory/caprover-hosts.yml` expose live infrastructure details in committed examples/comments.
- CapRover bootstrap uses HTTP on port 3000 before TLS, while credentials/tokens are transmitted in headers/body.
- `roles/caprover-base/tasks/main.yml` allows a broad “admin IP full access” rule plus a public bootstrap UI rule pattern; least-privilege should be tighter during bootstrap.

#### Maintainability issues

- The `openclaw` roles duplicate many near-identical `docker exec openclaw openclaw config set ...` tasks; a small helper include would reduce quoting drift and change-detection inconsistencies.
- Role metadata is absent across the repo, which hurts discoverability and reuse.
- `.ansible-lint` skips `var-naming[no-role-prefix]`; that is a conscious tradeoff, but it also removes a useful guardrail for a multi-role repo.

#### Missing validation / tests

- CI does not run `ansible-playbook --check --diff` for either `playbook.yml` or `caprover-playbook.yml`.
- CI/Molecule covers only `base`, `openclaw-config`, `openclaw-harden`, `reverse-proxy`, `maintenance`, `monitoring`, plus a trivial CapRover scenario. There is no role-level Molecule coverage for `openclaw-deploy`, `openclaw-integrate`, `agency-agents`, `verify`, `caprover-base`, `caprover-swarm`, or `caprover-apps`.
- `molecule/default/converge.yml` only validates preflight assertions; it does not exercise the real deployment roles.

### Finish

- Merge recommendation: block

- Exact verification commands to run locally
  ```bash
  pip install -r requirements.txt
  ansible-galaxy collection install -r requirements.yml

  yamllint .
  ansible-lint

  ansible-playbook playbook.yml --syntax-check
  ansible-playbook caprover-playbook.yml --syntax-check

  molecule test -s default
  molecule test -s caprover

  (cd roles/base && molecule test)
  (cd roles/openclaw-config && molecule test)
  (cd roles/openclaw-harden && molecule test)
  (cd roles/reverse-proxy && molecule test)
  (cd roles/maintenance && molecule test)

  ansible-playbook playbook.yml -i inventory/hosts.yml --check --diff --ask-vault-pass
  ansible-playbook caprover-playbook.yml -i inventory/caprover-hosts.yml --check --diff --ask-vault-pass
  ```

---

## Review run 2 — Claude command wrapper

Source instructions: `.claude/commands/ansible-review.md`

### Verdict

- FAIL

### Critical issues

- Severity: blocker
- File / path: ansible.cfg; caprover-playbook.yml; .github/workflows/ci.yml
- Task / handler / section: Default inventory wiring; CapRover usage header; CI syntax job
- Rule or principle violated: Loadability / structure — playbook must target the correct inventory and validation must exercise the intended host groups
- Evidence: ansible.cfg sets `inventory = inventory/hosts.yml`; `caprover-playbook.yml` usage says `ansible-playbook caprover-playbook.yml --ask-vault-pass`; CI runs `ansible-playbook caprover-playbook.yml --syntax-check` without `-i inventory/caprover-hosts.yml`; local run emitted `Could not match supplied host pattern, ignoring: caprover`, `caprover_leader`, `caprover_workers`
- Why it matters: The CapRover playbook can appear valid while targeting zero hosts; CI is not actually validating the intended inventory, and operators can run a no-op deployment by following the documented command
- Minimal fix: Make the CapRover inventory explicit in docs and CI, or add a dedicated ansible.cfg for the CapRover stack
- Corrected snippet or patch:
  ```yaml
  # .github/workflows/ci.yml
  - name: Run syntax check (caprover playbook)
    run: ansible-playbook -i inventory/caprover-hosts.yml caprover-playbook.yml --syntax-check
  ```
  ```yaml
  # caprover-playbook.yml header
  # ansible-playbook -i inventory/caprover-hosts.yml caprover-playbook.yml --ask-vault-pass
  ```

- Severity: blocker
- File / path: roles/caprover-swarm/tasks/main.yml
- Task / handler / section: `Check if CapRover is running` / `Deploy CapRover via Docker`
- Rule or principle violated: Idempotency / determinism — detection logic must match the resource creation method
- Evidence: the check uses `docker service ls --filter name=captain-captain`, but deployment uses `docker run -d --name captain-captain ...`; a container will never satisfy a swarm-service check
- Why it matters: Second and later runs will keep attempting `docker run --name captain-captain`, which fails because the container already exists; this blocks safe re-runs
- Minimal fix: Manage CapRover with `community.docker.docker_container`, or at minimum detect the existing container with `docker container inspect`
- Corrected snippet or patch:
  ```yaml
  - name: Deploy CapRover captain
    community.docker.docker_container:
      name: captain-captain
      image: "caprover/caprover:{{ caprover_version }}"
      restart_policy: unless-stopped
      published_ports:
        - "80:80"
        - "443:443"
        - "3000:3000"
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock
        - /captain:/captain
      env:
        ACCEPTED_TERMS: "true"
        MAIN_NODE_IP_ADDRESS: "{{ ansible_host }}"
      state: started
  ```

- Severity: high
- File / path: inventory/caprover-hosts.yml; caprover-playbook.yml
- Task / handler / section: CapRover inventory
- Rule or principle violated: Security — no hardcoded public IPs in committed inventory/examples
- Evidence: committed public IPs are present: `192.3.81.8`, `107.174.51.158`, `198.23.228.15`; the playbook header also embeds `192.3.81.8`
- Why it matters: This leaks deployment topology, reduces reusability, and violates the repository’s placeholder-based pattern used elsewhere (`YOUR_SERVER_IP`, `YOUR_STATIC_IP`)
- Minimal fix: Replace committed live addresses with placeholders or move them to an untracked/private inventory file
- Corrected snippet or patch:
  ```yaml
  all:
    children:
      caprover_leader:
        hosts:
          caprover-ny:
            ansible_host: YOUR_LEADER_IP
      caprover_workers:
        hosts:
          caprover-la:
            ansible_host: YOUR_WORKER1_IP
          caprover-chi:
            ansible_host: YOUR_WORKER2_IP
  ```

- Severity: high
- File / path: group_vars/caprover/vars.yml; roles/caprover-swarm/defaults/main.yml; group_vars/caprover/vars.yml
- Task / handler / section: CapRover bootstrap defaults / firewall ports
- Rule or principle violated: Security — no known default credential exposure on an internet-facing admin port
- Evidence: `caprover_initial_password: captain42` is committed in both defaults and vars; `caprover_ufw_allowed_ports` opens TCP 3000 publicly; password change happens later in `roles/caprover-swarm/tasks/main.yml`
- Why it matters: There is a bootstrap window where the public CapRover UI is reachable on port 3000 with a well-known default password if the run pauses or fails before rotation
- Minimal fix: Do not expose 3000 globally during bootstrap; restrict it to `caprover_admin_ip` until the captain password is changed successfully
- Corrected snippet or patch:
  ```yaml
  caprover_ufw_allowed_ports:
    - { port: 80,  proto: tcp, comment: "HTTP" }
    - { port: 443, proto: tcp, comment: "HTTPS" }
    - { port: 996, proto: tcp, comment: "CapRover registry" }
    - { port: 7946, proto: any, comment: "Docker Swarm node discovery" }
    - { port: 4789, proto: udp, comment: "Docker overlay network" }
    - { port: 2377, proto: tcp, comment: "Docker Swarm management" }

  - name: Allow CapRover UI only from admin IP during bootstrap
    community.general.ufw:
      rule: allow
      from_ip: "{{ caprover_admin_ip }}"
      port: "3000"
      proto: tcp
  ```

- Severity: high
- File / path: roles/caprover-apps/tasks/main.yml; roles/caprover-swarm/tasks/main.yml
- Task / handler / section: Authenticated CapRover API calls
- Rule or principle violated: Security — sensitive headers/tokens must be protected with `no_log: true`
- Evidence: many `ansible.builtin.uri` tasks send `x-captain-auth: "{{ cap_token }}"` or `x-captain-auth: "{{ caprover_auth_token }}"` without `no_log: true` (for example Prometheus/Uptime Kuma app registration and updates; root-domain/SSL/node queries)
- Why it matters: Auth tokens can leak in failure output, verbose logs, callback plugins, or CI artifacts
- Minimal fix: Add `no_log: true` to every authenticated CapRover API task, not only the ones carrying passwords
- Corrected snippet or patch:
  ```yaml
  - name: Register Prometheus app
    ansible.builtin.uri:
      url: "http://{{ ansible_host }}:3000/api/v2/user/apps/appDefinitions/register"
      method: POST
      body_format: json
      body:
        appName: prometheus
        hasPersistentData: true
      headers:
        x-captain-auth: "{{ cap_token }}"
      status_code: [200, 400]
    no_log: true
  ```

### Remaining findings

#### Definite rule violations

- `roles/caprover-swarm/tasks/main.yml` uses `validate_certs: false` on an authenticated HTTPS call to `https://captain.{{ caprover_root_domain }}/api/v2/user/system/nodes`; this disables TLS verification for a privileged API request.
- `roles/caprover-swarm/tasks/main.yml` accepts `status_code: [200, 400]` for password/domain/SSL mutations without validating the response body, so API-level failures can be treated as success.
- `roles/caprover-apps/tasks/main.yml` repeats the same `status_code: [200, 400]` pattern across app registration/update calls, again without asserting success semantics.

#### Likely bugs / idempotency risks

- `roles/openclaw-harden/tasks/main.yml`, `roles/openclaw-integrate/tasks/main.yml`, and `roles/agency-agents/tasks/main.yml` mark many mutating `docker exec` / `docker cp` tasks as `changed_when: false`; reruns may work, but change reporting is inaccurate and hides whether state was actually modified.
- `roles/openclaw-harden/tasks/main.yml` runs `openclaw security audit --deep --fix` with `changed_when: false`; an auto-fix task is explicitly mutating but reported as unchanged.
- `roles/verify/tasks/main.yml` checks the blocked egress path with `failed_when: false` and only prints the result; the role does not fail if `https://example.com` is unexpectedly reachable through the proxy.

#### Security risks

- `roles/caprover-swarm/tasks/main.yml` and `roles/caprover-apps/tasks/main.yml` call the CapRover API over `http://{{ ansible_host }}:3000` while sending passwords/tokens; use loopback or verified HTTPS where possible.
- `group_vars/caprover/vars.yml` and `roles/caprover-swarm/defaults/main.yml` commit the known default `captain42`; even as bootstrap metadata, it is a credential constant in repo state.
- `inventory/caprover-hosts.yml` stores live infrastructure coordinates in tracked inventory.

#### Maintainability issues

- The OpenClaw roles repeat large blocks of `docker exec openclaw openclaw config set ...`; a data-driven task include would be easier to audit and less error-prone.
- CapRover inventory/examples do not follow the placeholder convention used by the main OpenClaw inventory, which increases operator error and makes the repo less portable.

#### Missing validation / tests

- CI has `yamllint`, `ansible-lint`, syntax-check, and Molecule, but there is no `ansible-playbook --check --diff` validation for either playbook.
- The CapRover Molecule scenario (`molecule/caprover/molecule.yml`) runs only `dependency` and `syntax`; it does not `converge` or `verify` any CapRover behavior.
- There is no Molecule coverage for `openclaw-deploy`, `openclaw-integrate`, `verify`, or `agency-agents`, which are the most command-heavy roles.

### Finish

- Merge recommendation: block
- Exact verification commands to run locally:
  ```bash
  ansible-galaxy collection install -r requirements.yml
  yamllint .
  ansible-lint
  ansible-playbook playbook.yml --syntax-check
  ansible-playbook -i inventory/caprover-hosts.yml caprover-playbook.yml --syntax-check
  ansible-playbook playbook.yml --check --diff --ask-vault-pass
  ansible-playbook -i inventory/caprover-hosts.yml caprover-playbook.yml --check --diff --ask-vault-pass
  molecule test -s default
  molecule test -s caprover
  (cd roles/base && molecule test)
  (cd roles/openclaw-config && molecule test)
  (cd roles/openclaw-harden && molecule test)
  (cd roles/reverse-proxy && molecule test)
  (cd roles/maintenance && molecule test)
  ```
