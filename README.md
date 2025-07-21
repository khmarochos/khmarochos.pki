# Khmarochos PKI Collection

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Galaxy](https://img.shields.io/badge/galaxy-khmarochos.pki-blue)](https://galaxy.ansible.com/khmarochos/pki)

A comprehensive Ansible collection for managing Public Key Infrastructure (PKI) operations, including Certificate Authority creation, certificate issuance, and Kubernetes secret generation.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Modules](#modules)
- [Examples](#examples)
- [Kubernetes Integration](#kubernetes-integration)
- [PKI State Management](#pki-state-management)
- [Directory Structure](#directory-structure)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Hierarchical Certificate Authority Management**: Create and manage complex CA cascades with root and intermediate CAs
- **Flexible Certificate Issuance**: Support for server, client, and combined server-client certificates
- **Secure Key Management**: Automated private key generation with optional encryption and passphrase management
- **Kubernetes Integration**: Built-in script for generating Kubernetes TLS secrets from PKI certificates
- **Ansible Native**: Full integration with Ansible playbooks and change tracking
- **File-based Storage**: Organized directory structure with proper permissions for PKI assets

## Requirements

- **Ansible**: >= 2.9
- **Python**: >= 3.8
- **Dependencies**:
  - `cryptography` >= 3.0
  - `ansible-core`

## Installation

### From Ansible Galaxy

```bash
ansible-galaxy collection install khmarochos.pki
```

### From Source

```bash
git clone https://github.com/khmarochos/khmarochos.pki.git
cd khmarochos.pki
ansible-galaxy collection build collections/ansible_collections/khmarochos/pki/
ansible-galaxy collection install khmarochos-pki-*.tar.gz
```

### Requirements Installation

#### Using pip-tools (Recommended)

```bash
# Install pip-tools
pip install pip-tools

# Compile requirements.txt from requirements.in
pip-compile requirements.in

# Install dependencies
pip install -r requirements.txt
```

#### Direct Installation

```bash
pip install cryptography ansible-core
```

## Quick Start

### 1. Create a Basic PKI Configuration

Create a variables file (`vars/pki-config.yaml`):

```yaml
pki_cascade_configuration:
  __propagated:
    global_root_directory: "/opt/pki"
    domain: "example.com"
    certificate_subject_country_name: "US"
    certificate_subject_state_or_province_name: "California"
    certificate_subject_locality_name: "San Francisco"
    certificate_subject_organization_name: "Example Corp"
    certificate_subject_organizational_unit_name: "IT Department"
    certificate_subject_email_address: "admin@example.com"
    private_key_passphrase_random: true
  root:
    __parameters:
      name: "Root Certificate Authority (${domain})"
      private_key_encrypted: true
      private_key_size: 4096
      certificate_term: 3650  # 10 years
    intermediate:
      __parameters:
        default: true
        name: "Intermediate Certificate Authority (${domain})"
        private_key_encrypted: true
        private_key_size: 2048
        certificate_term: 1825  # 5 years
```

### 2. Create a Simple Playbook

Create `setup-pki.yaml`:

```yaml
---
- name: Setup PKI Infrastructure
  hosts: localhost
  vars_files:
    - vars/pki-config.yaml
  
  tasks:
    - name: Initialize PKI cascade
      khmarochos.pki.init_pki:
        pki_ca_cascade: "{{ pki_cascade_configuration }}"
        save_forced: false
      register: pki_result
    
    - name: Show PKI initialization result
      debug:
        msg: "PKI initialized with changes: {{ pki_result.changed }}"
```

### 3. Run the Playbook

```bash
ansible-playbook setup-pki.yaml
```

## Configuration

### PKI Cascade Structure

The PKI configuration uses a hierarchical structure with special keys:

- `__propagated`: Parameters inherited by all child CAs
- `__parameters`: CA-specific configuration

#### Global Parameters (`__propagated`)

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `global_root_directory` | Base directory for all PKI files | Required | `/opt/pki` |
| `domain` | Primary domain for certificates | Required | `example.com` |
| `certificate_subject_*` | Certificate subject fields | Required | See examples |
| `private_key_passphrase_random` | Auto-generate passphrases | `true` | `true/false` |

#### CA Parameters (`__parameters`)

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `name` | CA display name | `${nickname} Certificate Authority` | `Root CA` |
| `private_key_encrypted` | Encrypt private key | `false` | `true/false` |
| `private_key_size` | Key size in bits | `4096` | `2048/4096` |
| `certificate_term` | Certificate validity in days | `90` | `365/3650` |
| `default` | Default CA for operations | `false` | `true/false` |

### Certificate Types

| Type | Description | Usage |
|------|-------------|-------|
| `SERVER` | Server authentication | Web servers, APIs |
| `CLIENT` | Client authentication | User certificates |
| `SERVER_CLIENT` | Combined usage | Multi-purpose certificates |
| `NONE` | No specific usage | Custom certificates |

**Note:** Certificate types must be specified in uppercase as they correspond to the internal enum values.

## Modules

### khmarochos.pki.init_pki

Initialize and setup PKI cascade structure.

**Parameters:**
- `pki_ca_cascade` (dict, required): PKI configuration structure
- `load_if_exists` (bool): Load existing certificates (default: `true`)
- `save_if_needed` (bool): Save new certificates (default: `true`)
- `save_forced` (bool): Force save all certificates (default: `false`)

### khmarochos.pki.init_dictionary

Initialize PKI configuration dictionary for lookups.

**Parameters:**
- `pki_ca_cascade` (dict, required): PKI configuration structure

### khmarochos.pki.issue_everything

Issue certificates with private keys and CSRs.

**Parameters:**
- `pki_ca_cascade` (dict, required): PKI configuration structure
- `ca_nickname` (str, required): CA to use for signing
- `certificate_parameters` (dict, required): Certificate configuration

## Examples

### Complete Enterprise PKI Setup

```yaml
---
- name: Enterprise PKI Infrastructure
  hosts: localhost
  vars:
    pki_cascade_configuration:
      __propagated:
        global_root_directory: "/etc/pki"
        domain: "corp.example.com"
        certificate_subject_country_name: "US"
        certificate_subject_state_or_province_name: "New York"
        certificate_subject_locality_name: "New York City"
        certificate_subject_organization_name: "Example Corporation"
        certificate_subject_organizational_unit_name: "Information Technology"
        certificate_subject_email_address: "pki-admin@corp.example.com"
        private_key_passphrase_random: true
      
      # Root CA (offline, high security)
      root:
        __parameters:
          name: "Example Corp Root CA"
          private_key_encrypted: true
          private_key_size: 4096
          certificate_term: 7300  # 20 years
          strict: true
        
        # Intermediate CA for internal services
        internal:
          __parameters:
            default: true
            name: "Internal Services CA"
            private_key_encrypted: true
            private_key_size: 2048
            certificate_term: 3650  # 10 years
        
        # Intermediate CA for external services
        external:
          __parameters:
            name: "External Services CA"
            private_key_encrypted: true
            private_key_size: 2048
            certificate_term: 1825  # 5 years
      
      # Separate CA for Kubernetes
      kubernetes:
        __parameters:
          name: "Kubernetes Cluster CA"
          private_key_encrypted: false
          private_key_size: 2048
          certificate_term: 1095  # 3 years

  tasks:
    - name: Initialize PKI infrastructure
      khmarochos.pki.init_pki:
        pki_ca_cascade: "{{ pki_cascade_configuration }}"
      register: pki_init

    - name: Issue web server certificate
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_cascade_configuration }}"
        ca_nickname: "internal"
        certificate_parameters:
          nickname: "web-server"
          certificate_type: "server"
          certificate_term: 365
          certificate_subject_common_name: "web.corp.example.com"
          certificate_subject_alternative_names:
            - "DNS:web.corp.example.com"
            - "DNS:www.corp.example.com"
            - "IP:192.168.1.100"
          private_key_encrypted: false
          private_key_size: 2048
      register: web_cert

    - name: Issue client certificate for admin
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_cascade_configuration }}"
        ca_nickname: "internal"
        certificate_parameters:
          nickname: "admin-client"
          certificate_type: "client"
          certificate_term: 180
          certificate_subject_common_name: "admin@corp.example.com"
          certificate_subject_email_address: "admin@corp.example.com"
          private_key_encrypted: true
          private_key_passphrase_random: true
      register: admin_cert

    - name: Issue Kubernetes API server certificate
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_cascade_configuration }}"
        ca_nickname: "kubernetes"
        certificate_parameters:
          nickname: "kube-apiserver"
          certificate_type: "server"
          certificate_term: 365
          certificate_subject_common_name: "kube-apiserver"
          certificate_subject_alternative_names:
            - "DNS:kubernetes"
            - "DNS:kubernetes.default"
            - "DNS:kubernetes.default.svc"
            - "DNS:kubernetes.default.svc.cluster.local"
            - "IP:10.96.0.1"
            - "IP:192.168.1.10"
          private_key_encrypted: false
      register: k8s_cert

    - name: Display certificate information
      debug:
        msg: |
          Certificates issued:
          - Web Server: {{ web_cert.result.certificate.file }}
          - Admin Client: {{ admin_cert.result.certificate.file }}
          - Kubernetes API: {{ k8s_cert.result.certificate.file }}
```

### Certificate Renewal Playbook

```yaml
---
- name: Certificate Renewal
  hosts: localhost
  vars_files:
    - vars/pki-config.yaml
  
  tasks:
    - name: Check certificate expiration
      shell: |
        openssl x509 -in "{{ item }}" -noout -enddate
      register: cert_expiry
      loop:
        - "/etc/pki/internal/certs/web-server.crt"
        - "/etc/pki/internal/certs/api-server.crt"
      failed_when: false

    - name: Renew expiring certificates
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_cascade_configuration }}"
        ca_nickname: "internal"
        certificate_parameters:
          nickname: "{{ item.nickname }}"
          certificate_type: "{{ item.type }}"
          certificate_term: 365
          private_key_encrypted: false
          load_if_exists: true
          save_forced: true
      loop:
        - { nickname: "web-server", type: "server" }
        - { nickname: "api-server", type: "server" }
      when: "'Certificate will expire' in cert_expiry.stdout"
```

## Docker Usage

### Quick Start with Docker

The Docker container is designed to run your PKI playbooks with mounted configuration files:

```bash
# Build the container
docker build -t khmarochos/pki .

# Run with mounted files
docker run --rm \
  -v $(pwd)/pki:/app/pki \
  -v $(pwd)/vars/ca-tree.yaml:/app/vars/ca-tree.yaml:ro \
  -v $(pwd)/playbook.yaml:/app/playbook.yaml:ro \
  khmarochos/pki
```

### Required File Structure

The container expects the following mounted files:

```
your-project/
├── pki/                    # Your PKI directory tree (read/write)
├── vars/
│   ├── ca-tree.yaml       # CA hierarchy configuration (read-only)
│   └── certificates.yaml  # Certificate definitions (read-only)
└── playbook.yaml          # Your Ansible playbook (read-only)
```

### Quick Setup

Use the provided example files to get started quickly:

```bash
# Copy example files
cp vars/ca-tree.yaml.example vars/ca-tree.yaml
cp vars/certificates.yaml.example vars/certificates.yaml

# Edit the configuration files for your environment
# Then run with Docker (uses built-in default playbook)
docker run --rm \
  -v $(pwd)/pki:/app/pki \
  -v $(pwd)/vars/ca-tree.yaml:/app/vars/ca-tree.yaml:ro \
  -v $(pwd)/vars/certificates.yaml:/app/vars/certificates.yaml:ro \
  khmarochos/pki
```

### Using a Custom Playbook

If you want to use your own playbook instead of the default:

```bash
# Create your custom playbook
cp playbook.yaml my-custom-playbook.yaml
# Edit my-custom-playbook.yaml as needed

# Run with custom playbook
docker run --rm \
  -v $(pwd)/pki:/app/pki \
  -v $(pwd)/vars/ca-tree.yaml:/app/vars/ca-tree.yaml:ro \
  -v $(pwd)/vars/certificates.yaml:/app/vars/certificates.yaml:ro \
  -v $(pwd)/my-custom-playbook.yaml:/app/playbook.yaml:ro \
  khmarochos/pki
```

### Docker Compose

For easier management, use docker-compose with environment variables:

```bash
# Set environment variables
export PKI_DIR=/path/to/your/pki
export CA_TREE_CONFIG=/path/to/your/vars/ca-tree.yaml
export PLAYBOOK_FILE=/path/to/your/playbook.yaml

# Run the container
docker-compose up --rm
```

### Environment Variables for docker-compose

| Variable | Description | Default |
|----------|-------------|---------|
| `PKI_DIR` | Path to your PKI directory | `./pki` |
| `CA_TREE_CONFIG` | Path to CA hierarchy config | `./vars/ca-tree.yaml` |
| `PLAYBOOK_FILE` | Path to your playbook | `./playbook.yaml` |

### Example .env file

Create a `.env` file in your project directory:

```env
PKI_DIR=./pki
CA_TREE_CONFIG=./vars/ca-tree.yaml
PLAYBOOK_FILE=./setup-pki.yaml
```

### Running Custom Commands

You can override the default command to run custom operations:

```bash
# Run a different playbook
docker run --rm \
  -v $(pwd)/pki:/app/pki \
  -v $(pwd)/vars/ca-tree.yaml:/app/vars/ca-tree.yaml:ro \
  -v $(pwd)/playbook.yaml:/app/playbook.yaml:ro \
  khmarochos/pki \
  ansible-playbook ./playbook.yaml --tags certificates

# Generate Kubernetes secret
docker run --rm \
  -v $(pwd)/pki:/app/pki \
  khmarochos/pki \
  /app/scripts/make_secret.sh --pki-base /app/pki internal/web-server

# Interactive shell for debugging
docker run --rm -it \
  -v $(pwd)/pki:/app/pki \
  -v $(pwd)/vars/ca-tree.yaml:/app/vars/ca-tree.yaml:ro \
  -v $(pwd)/playbook.yaml:/app/playbook.yaml:ro \
  khmarochos/pki \
  bash
```

## Kubernetes Integration

### Generating Kubernetes Secrets

Use the included script to generate Kubernetes TLS secrets:

```bash
# Generate secret for a certificate
./scripts/make_secret.sh internal/web-server > web-server-tls.yaml

# Generate secret with custom options
./scripts/make_secret.sh \
    --ca-nickname internal \
    --pki-base /opt/pki \
    --certificate-with-chain \
    --ca-with-chain \
    web-server > web-server-tls.yaml

# Apply to Kubernetes
kubectl apply -f web-server-tls.yaml
```

### Script Options

| Option | Description | Default |
|--------|-------------|---------|
| `--pki-base` | PKI base directory | `${HOME}/pki` |
| `--ca-nickname` | CA nickname | From path |
| `--certificate-with-chain` | Include cert chain | Enabled |
| `--certificate-no-chain` | Exclude cert chain | Disabled |
| `--ca-with-chain` | Include CA chain | Enabled |
| `--ca-no-chain` | Exclude CA chain | Disabled |
| `--opaque` | Create Opaque secret | TLS type |
| `--no-ca` | Exclude CA certificate | Include CA |

### Example Kubernetes Secret Output

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: web-server-tls
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJTi... (base64 encoded certificate)
  tls.key: LS0tLS1CRUdJTi... (base64 encoded private key)
  ca.crt: LS0tLS1CRUdJTi... (base64 encoded CA certificate)
```

## PKI State Management

The collection includes powerful tools for monitoring and comparing your PKI infrastructure state over time.

### State Dumping

Capture the complete state of your PKI infrastructure:

```bash
# Dump current PKI state to JSON
python scripts/state_dump.py /opt/pki > /tmp/pki_state/current.json

# Dump with verbose logging
python scripts/state_dump.py -v /opt/pki -o /tmp/pki_state/current.json
```

The state dump includes comprehensive information about:
- **Certificate Authorities**: Hierarchical CA structure with full certificate chains
- **Certificates**: All CA and end-entity certificates with detailed metadata
- **Private Keys**: Key information, encryption status, and file metadata  
- **CSRs**: Certificate Signing Requests with extensions and key details
- **File Information**: Sizes, permissions, modification times for all PKI files

### State Comparison

Compare two PKI states to identify what changed between deployments:

```bash
# Compare states and show differences
python scripts/state_compare.py \
    /tmp/pki_state/before.json \
    /tmp/pki_state/after.json

# Force colored output (useful for CI/CD)
python scripts/state_compare.py --color before.json after.json

# Disable colors for text output
python scripts/state_compare.py --no-color before.json after.json > changes.txt
```

#### Sample Output

```
[:] Certificate Authorities (2)
├── root-ca
│   ├── [:] Certificate
│   │   ├── [+] Serial: 1234567890ABCDEF
│   │   ├── [:] Subject  
│   │   │   ├── [·] CN: Root CA
│   │   │   ├── [·] O: Example Corp
│   │   │   └── [·] C: US
│   │   ├── [:] SANs
│   │   │   └── [+] DNS:ca.example.com
│   │   └── [:] File
│   │       ├── [·] Path: /opt/pki/root-ca/certs/CA/root-ca.crt
│   │       ├── [+] Size: 1234 bytes
│   │       └── [·] Permissions: 644
│   └── [:] Private Key
│       ├── [·] Type & Size: 4096-bit RSA
│       └── [:] File
│           └── [+] Modified: 2024-07-21T10:30:45
└── intermediate-ca
    └── [... similar structure]

Summary:
  Certificate Authorities: 4 (+2 ~1 -1)
  Certificates: 15 (+8 ~3 -2)
  Private Keys: 15 (+8 ~1 -2)
  Certificate Signing Requests: 12 (+7 ~2 -1)
  Total changes: 46
```

#### Change Markers

| Marker | Meaning | Color |
|--------|---------|-------|
| `[+]` | Added | Green |
| `[-]` | Removed | Red |
| `[~]` | Changed | Yellow |
| `[·]` | Unchanged | White |
| `[:]` | Header | White Bold |

### Use Cases

#### Deployment Verification
```bash
# Before deployment
python scripts/state_dump.py /opt/pki > pre-deployment.json

# After deployment  
python scripts/state_dump.py /opt/pki > post-deployment.json

# Verify changes
python scripts/state_compare.py pre-deployment.json post-deployment.json
```

#### Certificate Renewal Tracking
```bash
# Weekly PKI state snapshots
python scripts/state_dump.py /opt/pki > "pki-state-$(date +%Y%m%d).json"

# Compare with previous week
python scripts/state_compare.py pki-state-20240714.json pki-state-20240721.json
```

#### Audit Trail
```bash
# Generate detailed audit report
python scripts/state_compare.py \
    --color \
    baseline.json current.json > audit-report.txt

# Include in CI/CD pipeline
if python scripts/state_compare.py expected.json actual.json; then
    echo "✓ PKI state matches expectations"
else
    echo "✗ PKI state differs - review changes above"
    exit 1
fi
```

### Integration with Automation

#### Ansible Playbook Integration
```yaml
- name: Capture PKI state before changes
  shell: python scripts/state_dump.py {{ pki_root_dir }}
  register: pki_state_before

- name: Apply PKI changes
  khmarochos.pki.init_pki:
    pki_ca_cascade: "{{ pki_configuration }}"

- name: Capture PKI state after changes  
  shell: python scripts/state_dump.py {{ pki_root_dir }}
  register: pki_state_after

- name: Show PKI changes
  shell: |
    echo "{{ pki_state_before.stdout }}" > /tmp/before.json
    echo "{{ pki_state_after.stdout }}" > /tmp/after.json
    python scripts/state_compare.py /tmp/before.json /tmp/after.json
```

#### GitOps Workflow
```bash
#!/bin/bash
# Save state to Git for tracking
DATE=$(date +%Y%m%d-%H%M)
python scripts/state_dump.py /opt/pki > "states/pki-${DATE}.json"
git add "states/pki-${DATE}.json"
git commit -m "PKI state snapshot: ${DATE}"

# Compare with previous state
PREV_STATE=$(ls states/pki-*.json | tail -2 | head -1)
python scripts/state_compare.py "${PREV_STATE}" "states/pki-${DATE}.json"
```

## Directory Structure

The collection organizes PKI files in a structured hierarchy:

```
{global_root_directory}/
├── {ca_nickname}/
│   ├── private/
│   │   └── CA/
│   │       ├── {ca_nickname}.key                    # CA private key
│   │       ├── {ca_nickname}.key_passphrase         # CA key passphrase
│   │       ├── {certificate_nickname}.key           # Certificate private keys
│   │       └── {certificate_nickname}.key_passphrase
│   ├── certs/
│   │   └── CA/
│   │       ├── {ca_nickname}.crt                    # CA certificate
│   │       ├── {ca_nickname}.chain.crt              # CA certificate chain
│   │       ├── {certificate_nickname}.crt           # Certificates
│   │       └── {certificate_nickname}.chain.crt     # Certificate chains
│   ├── csr/
│   │   └── CA/
│   │       ├── {ca_nickname}.csr                    # CA CSR
│   │       └── {certificate_nickname}.csr           # Certificate CSRs
│   └── crl/                                         # Certificate revocation lists
└── {other_ca_nickname}/
    └── ... (same structure)
```

### File Permissions

| Directory/File Type | Permissions | Description |
|---------------------|-------------|-------------|
| Root directories | `755` | Public readable |
| Private directories | `700` | Owner only |
| Private keys | `600` | Owner read/write only |
| Certificates | `644` | Public readable |
| Passphrases | `600` | Owner read/write only |

## Security Considerations

### Private Key Protection

- **Encryption**: Use `private_key_encrypted: true` for sensitive CAs
- **Passphrases**: Enable `private_key_passphrase_random: true` for automatic generation
- **File Permissions**: Private directories and keys use restrictive permissions
- **Storage**: Consider using encrypted filesystems for PKI directories

### Certificate Authority Best Practices

1. **Root CA Isolation**: Keep root CAs offline and use intermediate CAs for daily operations
2. **Key Sizes**: Use 4096-bit keys for root CAs, 2048-bit for intermediate CAs
3. **Certificate Lifetimes**: Limit certificate validity periods (90-365 days for end-entity certificates)
4. **Regular Rotation**: Implement certificate renewal procedures

### Network Security

- **Access Control**: Restrict access to PKI directories and Ansible controllers
- **Secure Transfer**: Use secure channels for certificate distribution
- **Monitoring**: Log all PKI operations for audit trails

## Troubleshooting

### Common Issues

#### Permission Denied Errors

```bash
# Check directory permissions
ls -la /opt/pki/

# Fix permissions if needed
sudo chown -R $(whoami): /opt/pki/
chmod -R 755 /opt/pki/
chmod -R 700 /opt/pki/*/private/
```

#### Certificate Validation Failures

```bash
# Verify certificate chain
openssl verify -CAfile /opt/pki/root/certs/CA/root.crt \
    /opt/pki/internal/certs/web-server.crt

# Check certificate details
openssl x509 -in /opt/pki/internal/certs/web-server.crt -text -noout
```

#### Passphrase Issues

```bash
# Check if passphrase file exists
ls -la /opt/pki/*/private/CA/*.key_passphrase

# Test private key with passphrase
openssl rsa -in /opt/pki/internal/private/CA/internal.key \
    -passin file:/opt/pki/internal/private/CA/internal.key_passphrase \
    -check
```

### Debug Mode

Enable Ansible debug mode for detailed output:

```bash
ansible-playbook -vvv setup-pki.yaml
```

### Log Files

Configure logging in the make_secret.sh script:

```bash
export LOG_FILE="/var/log/pki-operations.log"
export LOG_TIME_FORMAT="+%Y-%m-%d %H:%M:%S"
./scripts/make_secret.sh internal/web-server
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Run tests: `python -m pytest collections/ansible_collections/khmarochos/pki/tests/`
5. Commit your changes: `git commit -am 'Add feature'`
. Push to the branch: `git push origin feature-name`
7. Submit a pull request

### Development Setup

```bash
git clone https://github.com/khmarochos/khmarochos.pki.git
cd khmarochos.pki
pip install -r requirements-dev.txt  # If available
python -m pytest collections/ansible_collections/khmarochos/pki/tests/unit/
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Author

**Volodymyr Melnyk** - [volodymyr@melnyk.host](mailto:volodymyr@melnyk.host)

## Links

- [GitHub Repository](https://github.com/khmarochos/khmarochos.pki)
- [Ansible Galaxy](https://galaxy.ansible.com/khmarochos/pki)
- [Documentation Wiki](https://github.com/khmarochos/khmarochos.pki/wiki)
- [Issue Tracker](https://github.com/khmarochos/khmarochos.pki/issues)