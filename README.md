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

### PKI Cascade Configuration Structure

The PKI configuration uses a sophisticated hierarchical structure that enables both parameter inheritance and CA-specific customization. Understanding this structure is crucial for effective PKI management.

#### Core Configuration Concepts

**Hierarchical Inheritance**: Parameters defined at higher levels are automatically inherited by child CAs unless explicitly overridden.

**Special Keys**: The configuration uses two special keys for advanced functionality:
- `__propagated`: Global parameters that cascade down to all child CAs
- `__parameters`: CA-specific configuration that applies only to that particular CA

**Nickname-based Organization**: Each CA is identified by its position in the hierarchy, creating a natural nickname system (e.g., `root`, `root.intermediate`, `root.intermediate.server`).

#### Configuration Anatomy

```yaml
pki_cascade_configuration:
  __propagated:                    # Global settings for entire PKI
    global_root_directory: "/opt/pki"
    domain: "example.com"
    # ... global parameters
  
  root:                           # Root CA (nickname: "root")  
    __parameters:                 # Settings specific to root CA
      name: "Root Certificate Authority"
      certificate_term: 3650
      # ... root-specific parameters
    
    intermediate:                 # Intermediate CA (nickname: "intermediate")
      __parameters:               # Settings for intermediate CA
        name: "Intermediate CA"
        default: true            # This CA is default for certificate issuance
        # ... intermediate-specific parameters
      
      server:                    # Server CA (nickname: "server")
        __parameters:            # Settings for server certificate CA
          name: "Server Certificate CA"
          # ... server CA parameters
      
      client:                    # Client CA (nickname: "client") 
        __parameters:            # Settings for client certificate CA
          name: "Client Certificate CA"
          # ... client CA parameters
```

#### Global Parameters (`__propagated`)

These parameters are inherited by all CAs in the hierarchy and define the foundational PKI settings:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `global_root_directory` | str | ✓ | - | Base directory where all PKI files and subdirectories will be created |
| `domain` | str | ✓ | - | Primary domain used in certificate subject names and as template variable |
| `certificate_subject_country_name` | str | ✓ | - | Two-letter ISO country code (e.g., "US", "GB", "DE") |
| `certificate_subject_state_or_province_name` | str | ✓ | - | Full state or province name |
| `certificate_subject_locality_name` | str | ✓ | - | City or locality name |
| `certificate_subject_organization_name` | str | ✓ | - | Organization or company name |
| `certificate_subject_organizational_unit_name` | str | ✗ | - | Department or organizational unit |
| `certificate_subject_email_address` | str | ✗ | - | Contact email address for the PKI |
| `private_key_passphrase_random` | bool | ✗ | `true` | Auto-generate random passphrases for encrypted keys |
| `private_key_passphrase_length` | int | ✗ | `32` | Length of generated passphrases |
| `certificate_default_term` | int | ✗ | `90` | Default certificate validity period in days |

#### CA-Specific Parameters (`__parameters`)

These parameters customize individual CAs and override inherited values:

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | str | ✗ | `"${nickname} Certificate Authority"` | Human-readable CA name (supports variable substitution) |
| `private_key_encrypted` | bool | ✗ | `false` | Whether to encrypt the CA's private key with a passphrase |
| `private_key_size` | int | ✗ | `4096` | RSA key size in bits (2048, 3072, 4096) |
| `certificate_term` | int | ✗ | Inherited | Certificate validity period in days for this CA |
| `certificate_type` | str | ✗ | `"ca"` | Certificate type (`"ca"` for intermediate CAs) |
| `default` | bool | ✗ | `false` | Whether this CA is the default for certificate issuance operations |
| `strict` | bool | ✗ | `false` | Enable strict validation and enhanced security checks |

#### Variable Substitution

The configuration supports dynamic variable substitution using `${variable_name}` syntax:

**Available Variables:**
- `${nickname}`: The CA's nickname in the hierarchy
- `${domain}`: The domain from `__propagated` section
- `${parent_nickname}`: Parent CA's nickname (for intermediate CAs)

**Example:**
```yaml
root:
  __parameters:
    name: "Root CA for ${domain}"           # Becomes: "Root CA for example.com"
  intermediate:
    __parameters:
      name: "${nickname} CA (${domain})"    # Becomes: "intermediate CA (example.com)"
```

#### Configuration Inheritance Rules

1. **Global Propagation**: All `__propagated` parameters are available to every CA
2. **Parameter Override**: `__parameters` values override inherited values
3. **Hierarchical Cascade**: Child CAs inherit from parent CAs, not just global settings
4. **Default Precedence**: Explicit values > Parent CA values > Global values > System defaults

#### Advanced Configuration Examples

**Multi-Environment Setup:**
```yaml
pki_cascade_configuration:
  __propagated:
    global_root_directory: "/opt/multi-env-pki"
    domain: "corp.example.com"
    certificate_subject_organization_name: "Example Corporation"
    private_key_passphrase_random: true
  
  root:
    __parameters:
      name: "Corporate Root CA"
      private_key_size: 4096
      certificate_term: 7300  # 20 years
      strict: true
    
    production:
      __parameters:
        name: "Production Environment CA"
        certificate_term: 365
        default: true
      
      web:
        __parameters:
          name: "Production Web Services CA"
          certificate_term: 90
      
      api:
        __parameters:
          name: "Production API Services CA"
          certificate_term: 30
    
    development:
      __parameters:
        name: "Development Environment CA"
        certificate_term: 30
        private_key_encrypted: false  # Less security for dev
    
    staging:
      __parameters:
        name: "Staging Environment CA"  
        certificate_term: 90
```

**Geographic Distribution:**
```yaml
pki_cascade_configuration:
  __propagated:
    global_root_directory: "/opt/global-pki"
    certificate_subject_organization_name: "Global Corp"
    
  global-root:
    __parameters:
      name: "Global Root Certificate Authority"
      certificate_term: 10950  # 30 years
      private_key_size: 4096
    
    us-region:
      __propagated:
        certificate_subject_country_name: "US"
        certificate_subject_state_or_province_name: "California"
      __parameters:
        name: "US Regional CA"
        certificate_term: 1825  # 5 years
      
      us-west:
        __propagated:
          certificate_subject_locality_name: "San Francisco"
        __parameters:
          name: "US West Coast CA"
          default: true
      
      us-east:
        __propagated:
          certificate_subject_locality_name: "New York"
        __parameters:
          name: "US East Coast CA"
    
    eu-region:
      __propagated:
        certificate_subject_country_name: "DE"
        certificate_subject_state_or_province_name: "Bavaria"
        certificate_subject_locality_name: "Munich"
      __parameters:
        name: "EU Regional CA"
        certificate_term: 1825  # 5 years
```

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

**Purpose:** Initialize and setup complete PKI infrastructure with hierarchical Certificate Authority cascades.

**Description:**
This module is the foundation of PKI infrastructure management. It creates directory structures, generates private keys, issues CA certificates, and establishes the complete certificate authority hierarchy according to your configuration. The module intelligently handles both fresh installations and updates to existing PKI structures.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `pki_ca_cascade` | dict | ✓ | - | Complete PKI configuration structure defining CA hierarchy, global parameters, and CA-specific settings |
| `load_if_exists` | bool | ✗ | `true` | Load and integrate existing PKI certificates and keys if found in the file system |
| `save_if_needed` | bool | ✗ | `true` | Save newly generated certificates and keys to disk when changes are detected |
| `save_forced` | bool | ✗ | `false` | Force regeneration and saving of all PKI components, even if they already exist |

**Return Values:**

| Key | Type | Description |
|-----|------|-------------|
| `result` | dict | Complete PKI cascade structure with all generated components |
| `changed` | bool | Whether any changes were made to the PKI infrastructure |
| `cascade_summary` | dict | Summary statistics of CAs created, certificates issued, and keys generated |

**Use Cases:**
- **Initial PKI Setup**: Create complete PKI infrastructure from scratch
- **PKI Updates**: Add new CAs or modify existing CA configurations
- **Infrastructure Recovery**: Restore PKI from configuration after disaster
- **Development/Testing**: Quickly bootstrap PKI for development environments

**Example - Basic Setup:**
```yaml
- name: Initialize basic PKI infrastructure
  khmarochos.pki.init_pki:
    pki_ca_cascade:
      __propagated:
        global_root_directory: "/opt/pki"
        domain: "example.com"
        certificate_subject_country_name: "US"
        certificate_subject_organization_name: "Example Corp"
      root:
        __parameters:
          name: "Root Certificate Authority"
          private_key_encrypted: true
          certificate_term: 3650
```

**Example - Enterprise Hierarchy:**
```yaml
- name: Initialize enterprise PKI with intermediate CAs
  khmarochos.pki.init_pki:
    pki_ca_cascade:
      __propagated:
        global_root_directory: "/etc/enterprise-pki"
        domain: "corp.example.com"
        private_key_passphrase_random: true
      root:
        __parameters:
          name: "Enterprise Root CA"
          private_key_size: 4096
          certificate_term: 7300  # 20 years
        intermediate:
          __parameters:
            name: "Intermediate CA for Services"
            default: true
            certificate_term: 1825  # 5 years
          server:
            __parameters:
              name: "Server Certificate CA"
              certificate_term: 365
          client:
            __parameters:
              name: "Client Certificate CA"  
              certificate_term: 180
```

---

### khmarochos.pki.init_dictionary

**Purpose:** Initialize PKI configuration dictionary for efficient CA and certificate lookups.

**Description:**
This utility module processes the PKI cascade configuration and creates optimized lookup dictionaries. It's primarily used internally by other modules but can be useful for custom automation scripts that need to query PKI configuration programmatically.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `pki_ca_cascade` | dict | ✓ | - | PKI configuration structure to process into lookup dictionaries |

**Return Values:**

| Key | Type | Description |
|-----|------|-------------|
| `result` | dict | Dictionary mapping containing CA lookups, default CA identifications, and configuration inheritance chains |
| `changed` | bool | Always `false` - this module only processes data, doesn't modify files |

**Use Cases:**
- **Configuration Validation**: Verify PKI configuration before applying changes
- **Custom Automation**: Build custom scripts that need to query CA relationships
- **Debugging**: Understand how configuration inheritance works in complex hierarchies

**Example:**
```yaml
- name: Process PKI configuration for validation
  khmarochos.pki.init_dictionary:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
  register: pki_dict

- name: Show default CA
  debug:
    msg: "Default CA is: {{ pki_dict.result.default_ca_nickname }}"
```

---

### khmarochos.pki.issue_everything

**Purpose:** Issue end-entity certificates with all required components (private keys, CSRs, passphrases).

**Description:**
This module handles the complete certificate issuance workflow for end-entity certificates (server, client, or combined certificates). It generates private keys, creates certificate signing requests, issues certificates from the specified CA, and manages passphrases - all in a single operation with full Ansible change tracking.

**Parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `pki_ca_cascade` | dict | ✓ | - | PKI configuration structure containing the target CA |
| `ca_nickname` | str | ✓ | - | Nickname of the Certificate Authority to use for issuing the certificate |
| `certificate_parameters` | dict | ✓ | - | Complete certificate specification including subject, extensions, key parameters, and validity |
| `hide_passphrase_value` | bool | ✗ | `true` | Hide actual passphrase values in Ansible output for security |

**Certificate Parameters Structure:**

The `certificate_parameters` dictionary supports extensive configuration:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `nickname` | str | ✓ | Unique identifier for the certificate within the CA |
| `certificate_type` | str | ✓ | Certificate usage: `"SERVER"`, `"CLIENT"`, `"SERVER_CLIENT"`, or `"NONE"` |
| `certificate_term` | int | ✗ | Certificate validity period in days (inherits from CA if not specified) |
| `certificate_subject_common_name` | str | ✓ | Common Name (CN) for the certificate subject |
| `certificate_subject_alternative_names` | list | ✗ | List of Subject Alternative Names (DNS names, IP addresses, etc.) |
| `private_key_encrypted` | bool | ✗ | Whether to encrypt the private key with a passphrase |
| `private_key_size` | int | ✗ | RSA key size in bits (2048, 4096, etc.) |
| `private_key_passphrase_random` | bool | ✗ | Generate random passphrase if encryption is enabled |

**Subject Fields (optional):**
- `certificate_subject_country_name` (str): Two-letter country code
- `certificate_subject_state_or_province_name` (str): State or province name  
- `certificate_subject_locality_name` (str): City or locality name
- `certificate_subject_organization_name` (str): Organization name
- `certificate_subject_organizational_unit_name` (str): Organizational unit
- `certificate_subject_email_address` (str): Email address

**Return Values:**

| Key | Type | Description |
|-----|------|-------------|
| `result.certificate` | dict | Certificate properties including file paths, subject details, validity dates, and extensions |
| `result.private_key` | dict | Private key properties including encryption status, key size, and file location |
| `result.certificate_signing_request` | dict | CSR properties and file information |
| `result.passphrase` | dict | Passphrase information (value hidden by default) |
| `changed` | bool | Whether any new certificates or keys were generated |

**Use Cases:**
- **Web Server Certificates**: Issue TLS certificates for HTTPS services
- **Client Authentication**: Generate certificates for user/device authentication
- **Service-to-Service**: Create certificates for microservice mutual TLS
- **API Security**: Issue certificates for REST API authentication

**Example - Web Server Certificate:**
```yaml
- name: Issue certificate for web server
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "intermediate"
    certificate_parameters:
      nickname: "web-server"
      certificate_type: "SERVER"
      certificate_term: 365
      certificate_subject_common_name: "www.example.com"
      certificate_subject_alternative_names:
        - "DNS:www.example.com"
        - "DNS:example.com"  
        - "DNS:api.example.com"
        - "IP:192.168.1.100"
      private_key_encrypted: false
      private_key_size: 2048
  register: web_cert

- name: Show certificate location
  debug:
    msg: "Certificate saved to: {{ web_cert.result.certificate.file }}"
```

**Example - Client Certificate with Encryption:**
```yaml  
- name: Issue encrypted client certificate
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "client-ca"
    certificate_parameters:
      nickname: "john-doe"
      certificate_type: "CLIENT"
      certificate_term: 90
      certificate_subject_common_name: "john.doe@example.com"
      certificate_subject_email_address: "john.doe@example.com"
      private_key_encrypted: true
      private_key_passphrase_random: true
      private_key_size: 2048
    hide_passphrase_value: true
  register: client_cert

- name: Show client certificate details  
  debug:
    msg: |
      Client certificate issued:
      - Certificate: {{ client_cert.result.certificate.file }}
      - Private Key: {{ client_cert.result.private_key.file }}
      - Encrypted: {{ client_cert.result.private_key.encrypted }}
```

**Example - Kubernetes Service Certificate:**
```yaml
- name: Issue certificate for Kubernetes API server
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "kubernetes"
    certificate_parameters:
      nickname: "kube-apiserver"
      certificate_type: "SERVER"
      certificate_term: 365
      certificate_subject_common_name: "kube-apiserver"
      certificate_subject_alternative_names:
        - "DNS:kubernetes"
        - "DNS:kubernetes.default"
        - "DNS:kubernetes.default.svc"
        - "DNS:kubernetes.default.svc.cluster.local"
        - "IP:10.96.0.1"        # Cluster IP
        - "IP:192.168.1.10"     # Master node IP
      private_key_encrypted: false
      private_key_size: 2048
```

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

## Environment Variables

The PKI collection supports environment variables for configuring file paths and directories, allowing flexible deployment across different environments.

### Supported Environment Variables

| Variable | Description | Default Value | Used In |
|----------|-------------|---------------|---------|
| `CA_TREE_FILE` | Path to the CA hierarchy configuration file | `./vars/ca-tree.yaml` | Ansible playbook, Docker |
| `CERTIFICATES_FILE` | Path to the certificates configuration file | `./vars/certificates.yaml` | Ansible playbook, Docker |
| `ARTIFACTS_DIRECTORY` | Path to the PKI artifacts directory where certificates, keys, and CRLs are stored | `./pki` | Ansible playbook, Docker |
| `PLAYBOOK_FILE` | Path to the Ansible playbook file | `./playbook.yaml` | Docker only |
| `PKI_STATE_DIR` | Path to the state snapshots directory | Temporary directory | Docker only |

### Usage Examples

#### With Ansible Playbook

```bash
# Override configuration file paths
CA_TREE_FILE=/custom/path/ca-hierarchy.yaml \
CERTIFICATES_FILE=/custom/path/certs.yaml \
ARTIFACTS_DIRECTORY=/custom/pki/storage \
ansible-playbook playbook.yaml

# Using export for multiple runs
export CA_TREE_FILE=/etc/pki/config/ca-tree.yaml
export CERTIFICATES_FILE=/etc/pki/config/certificates.yaml
export ARTIFACTS_DIRECTORY=/var/lib/pki
ansible-playbook playbook.yaml
```

#### With Docker

```bash
# Override all paths
docker run --rm \
  -e CA_TREE_FILE=/app/custom/ca-tree.yaml \
  -e CERTIFICATES_FILE=/app/custom/certificates.yaml \
  -e ARTIFACTS_DIRECTORY=/app/custom-pki \
  -v $(pwd)/custom:/app/custom \
  khmarochos/pki

# Using environment file
cat > .env <<EOF
CA_TREE_FILE=/app/config/ca-tree.yaml
CERTIFICATES_FILE=/app/config/certificates.yaml
ARTIFACTS_DIRECTORY=/app/pki-storage
EOF

docker run --rm --env-file .env \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/pki-storage:/app/pki-storage \
  khmarochos/pki
```

### Configuration Precedence

1. Environment variables (highest priority)
2. Default values in playbook/scripts
3. System defaults (lowest priority)

The environment variables are particularly useful for:
- CI/CD pipelines with different configurations per environment
- Containerized deployments with mounted volumes
- Multi-tenant PKI setups with separate configuration files
- Development vs. production environment separation

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
export ARTIFACTS_DIRECTORY=/path/to/your/pki
export CA_TREE_FILE=/path/to/your/vars/ca-tree.yaml
export CERTIFICATES_FILE=/path/to/your/vars/certificates.yaml
export PLAYBOOK_FILE=/path/to/your/playbook.yaml

# Run the container
docker-compose up --rm
```

### Environment Variables for docker-compose

| Variable | Description | Default |
|----------|-------------|---------|
| `ARTIFACTS_DIRECTORY` | Path to your PKI artifacts directory | `./pki` |
| `CA_TREE_FILE` | Path to CA hierarchy config | `./vars/ca-tree.yaml` |
| `CERTIFICATES_FILE` | Path to certificates config | `./vars/certificates.yaml` |
| `PLAYBOOK_FILE` | Path to your playbook | `./playbook.yaml` |

### Example .env file

Create a `.env` file in your project directory:

```env
ARTIFACTS_DIRECTORY=./pki
CA_TREE_FILE=./vars/ca-tree.yaml
CERTIFICATES_FILE=./vars/certificates.yaml
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