# Ansible controller image for the clincher OpenClaw deployment toolkit.
# Provides a self-contained environment for running the deployment playbooks
# without installing Ansible locally.
#
# Usage:
#   docker run --rm -it \
#     -v ~/.ssh:/root/.ssh:ro \
#     -v $(pwd)/group_vars:/ansible/group_vars:ro \
#     clincher ansible-playbook playbook.yml -i inventory/hosts.yml

FROM python:3.12-alpine

RUN apk add --no-cache \
    git \
    openssh-client \
    sshpass

WORKDIR /ansible

COPY requirements.yml ./
RUN pip install --no-cache-dir ansible==13.4.0 && \
    ansible-galaxy collection install -r requirements.yml

COPY . .

ENTRYPOINT ["ansible-playbook"]
CMD ["--help"]
