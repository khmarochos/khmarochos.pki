FROM python:3.12-slim

LABEL maintainer="Volodymyr Melnyk <volodymyr@melnyk.host>"
LABEL description="khmarochos.pki - PKI management tool with Ansible"
LABEL version="0.0.5"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV ANSIBLE_HOST_KEY_CHECKING=False
ENV ANSIBLE_RETRY_FILES_ENABLED=False
ENV ANSIBLE_SSH_PIPELINING=True
ENV ANSIBLE_COLLECTIONS_PATH=/app/collections
ENV PLAYBOOK_FILE=/app/playbook.yaml
ENV CA_TREE_FILE=/app/vars/ca-tree.yaml
ENV CERTIFICATES_FILE=/app/vars/certificates.yaml
ENV PKI_STATE_DIR=""
ENV FORCE_COLOR=False

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the collection and scripts
COPY collections/ /app/collections/
COPY scripts/ /app/scripts/

# Ensure bash-helpers submodule is included
# The build will fail if the submodule is not initialized
RUN test -d /app/scripts/lib/bash-helpers/lib || \
    (echo "ERROR: bash-helpers submodule not found!" && \
     echo "Please run 'git submodule update --init --recursive' before building" && \
     exit 1)

# Copy the default playbook
COPY playbook.yaml /app/playbook-default.yaml

# Set proper permissions for scripts
RUN chmod +x /app/scripts/*.sh

# Copy and set up entrypoint script
COPY scripts/docker-entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command - no arguments to trigger PKI state tracking
CMD []