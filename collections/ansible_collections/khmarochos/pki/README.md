# Ansible Collection - khmarochos.pki

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Galaxy](https://img.shields.io/badge/galaxy-khmarochos.pki-blue)](https://galaxy.ansible.com/khmarochos/pki)

A comprehensive Ansible collection for managing Public Key Infrastructure (PKI) operations, including Certificate Authority creation, certificate issuance, and Kubernetes secret generation.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Modules](#modules)
- [Roles](#roles)
- [Plugins](#plugins)
- [Configuration Structure](#configuration-structure)
- [Examples](#examples)
- [Directory Structure](#directory-structure)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Hierarchical Certificate Authority Management**: Create and manage complex CA cascades with root and intermediate CAs
- **Flexible Certificate Issuance**: Support for server, client, and combined server-client certificates
- **Secure Key Management**: Automated private key generation with optional encryption and passphrase management
- **Kubernetes Integration**: Built-in utilities for generating Kubernetes TLS secrets from PKI certificates
- **Ansible Native**: Full integration with Ansible playbooks and change tracking
- **File-based Storage**: Organized directory structure with proper permissions for PKI assets
- **Dynamic Configuration**: Property-based configuration with string interpolation support

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
    certificate_subject_organization_name: "Example Corp"
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

**Example:**
```yaml
- name: Initialize PKI infrastructure
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
        intermediate:
          __parameters:
            default: true
            name: "Intermediate CA"
            certificate_term: 1825
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

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `nickname` | str | ✓ | Unique identifier for the certificate within the CA |
| `certificate_type` | str | ✓ | Certificate usage: `"SERVER"`, `"CLIENT"`, `"SERVER_CLIENT"`, or `"NONE"` |
| `certificate_term` | int | ✗ | Certificate validity period in days |
| `certificate_subject_common_name` | str | ✓ | Common Name (CN) for the certificate subject |
| `certificate_subject_alternative_names` | list | ✗ | List of Subject Alternative Names (DNS names, IP addresses, etc.) |
| `private_key_encrypted` | bool | ✗ | Whether to encrypt the private key with a passphrase |
| `private_key_size` | int | ✗ | RSA key size in bits (2048, 4096, etc.) |

**Return Values:**

| Key | Type | Description |
|-----|------|-------------|
| `result.certificate` | dict | Certificate properties including file paths, subject details, validity dates, and extensions |
| `result.private_key` | dict | Private key properties including encryption status, key size, and file location |
| `result.certificate_signing_request` | dict | CSR properties and file information |
| `result.passphrase` | dict | Passphrase information (value hidden by default) |
| `changed` | bool | Whether any new certificates or keys were generated |

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
    ca_nickname: "intermediate"
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
```

## Roles

### khmarochos.pki.cascade

**Purpose:** Manages the deployment and configuration of PKI cascades, including installation of required packages and setup of hierarchical Certificate Authority structures.

**Key Features:**
- Automated package installation for PKI dependencies
- Hierarchical CA cascade creation
- Secure private key and certificate management
- Cross-platform support (Ubuntu, CentOS, RHEL, Rocky Linux, AlmaLinux)

**Usage:**
```yaml
- hosts: pki_servers
  roles:
    - role: khmarochos.pki.cascade
      vars:
        pki_cascade_configuration:
          __propagated:
            global_root_directory: /opt/pki
            domain: "example.com"
            certificate_subject_country_name: "US"
            certificate_subject_organization_name: "Example Corp"
          root:
            __parameters:
              name: "Company Root CA"
              certificate_term: 3650
            intermediate:
              __parameters:
                name: "Company Intermediate CA"
                certificate_term: 1825
```

## Plugins

### khmarochos.pki.pki_dictionary

**Purpose:** Lookup plugin for PKI dictionary access and configuration queries.

**Usage:**
```yaml
- name: Get CA information
  debug:
    msg: "{{ lookup('khmarochos.pki.pki_dictionary', 'ca_info', ca_nickname='intermediate') }}"
```

## Configuration Structure

### PKI Cascade Configuration

The PKI configuration uses a sophisticated hierarchical structure that enables both parameter inheritance and CA-specific customization.

#### Core Configuration Concepts

**Hierarchical Inheritance**: Parameters defined at higher levels are automatically inherited by child CAs unless explicitly overridden.

**Special Keys**: The configuration uses two special keys for advanced functionality:
- `__propagated`: Global parameters that cascade down to all child CAs
- `__parameters`: CA-specific configuration that applies only to that particular CA

**Nickname-based Organization**: Each CA is identified by its position in the hierarchy, creating a natural nickname system (e.g., `root`, `root.intermediate`, `root.intermediate.server`).

#### Global Parameters (`__propagated`)

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
        certificate_subject_state_or_province_name: "California"
        certificate_subject_locality_name: "San Francisco"
        certificate_subject_organization_name: "Example Corporation"
        certificate_subject_organizational_unit_name: "IT Department"
        certificate_subject_email_address: "pki-admin@corp.example.com"
        private_key_passphrase_random: true
      
      root:
        __parameters:
          name: "Example Corp Root CA"
          private_key_encrypted: true
          private_key_size: 4096
          certificate_term: 7300  # 20 years
          strict: true
        
        internal:
          __parameters:
            default: true
            name: "Internal Services CA"
            private_key_encrypted: true
            private_key_size: 2048
            certificate_term: 3650  # 10 years
        
        external:
          __parameters:
            name: "External Services CA"
            private_key_encrypted: true
            private_key_size: 2048
            certificate_term: 1825  # 5 years

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
          certificate_type: "SERVER"
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
          certificate_type: "CLIENT"
          certificate_term: 180
          certificate_subject_common_name: "admin@corp.example.com"
          certificate_subject_email_address: "admin@corp.example.com"
          private_key_encrypted: true
          private_key_passphrase_random: true
      register: admin_cert
```

### Certificate Renewal Playbook

```yaml
---
- name: Certificate Renewal
  hosts: localhost
  vars_files:
    - vars/pki-config.yaml
  
  tasks:
    - name: Renew expiring certificates
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_cascade_configuration }}"
        ca_nickname: "internal"
        certificate_parameters:
          nickname: "{{ item.nickname }}"
          certificate_type: "{{ item.type }}"
          certificate_term: 365
          private_key_encrypted: false
          save_forced: true
      loop:
        - { nickname: "web-server", type: "SERVER" }
        - { nickname: "api-server", type: "SERVER" }
```

## Directory Structure

The PKI system organizes files in a structured hierarchy:

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

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Run tests: `python -m pytest collections/ansible_collections/khmarochos/pki/tests/`
5. Commit your changes: `git commit -am 'Add feature'`
6. Push to the branch: `git push origin feature-name`
7. Submit a pull request

### Development Setup

```bash
git clone https://github.com/khmarochos/khmarochos.pki.git
cd khmarochos.pki
pip install -r requirements.txt
python -m pytest collections/ansible_collections/khmarochos/pki/tests/unit/
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Author Information

**Volodymyr Melnyk** - [volodymyr@melnyk.host](mailto:volodymyr@melnyk.host)

This collection was created by Volodymyr Melnyk.
