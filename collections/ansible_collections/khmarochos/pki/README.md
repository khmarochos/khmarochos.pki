# Ansible Collection - khmarochos.pki

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Galaxy](https://img.shields.io/badge/galaxy-khmarochos.pki-blue)](https://galaxy.ansible.com/khmarochos/pki)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Ansible](https://img.shields.io/badge/ansible-2.9%2B-red)](https://www.ansible.com/)

A production-ready Ansible collection for building and managing enterprise Public Key Infrastructure (PKI) environments. This collection provides a complete solution for creating hierarchical Certificate Authorities (CAs), issuing certificates, and integrating with modern infrastructure platforms like Kubernetes.

## 🎯 Why Use This Collection?

Managing PKI infrastructure is complex and error-prone. This collection simplifies PKI operations by providing:

- **Zero-to-PKI in Minutes**: Deploy complete PKI infrastructure with a single playbook
- **Enterprise-Ready**: Production-tested modules supporting complex hierarchical CA structures
- **Security-First Design**: Encrypted private keys, secure passphrases, and proper file permissions by default
- **Kubernetes Native**: Built-in support for generating TLS secrets for Kubernetes deployments
- **Fully Idempotent**: All operations are safe to run multiple times with proper change tracking
- **Flexible Architecture**: Supports any CA hierarchy from simple single-CA to complex multi-tier structures

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Core Concepts](#-core-concepts)
- [Modules Reference](#-modules-reference)
- [Usage Examples](#-usage-examples)
- [PKI Architecture](#-pki-architecture)
- [Configuration Guide](#-configuration-guide)
- [Best Practices](#-best-practices)
- [Security](#-security)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)

## 🚀 Quick Start

### Minimal PKI Setup

Create a basic PKI infrastructure with root and intermediate CAs:

```yaml
---
- name: Deploy PKI Infrastructure
  hosts: localhost
  gather_facts: no
  tasks:
    - name: Initialize PKI with two-tier CA hierarchy
      khmarochos.pki.init_pki:
        pki_ca_cascade:
          __propagated:
            global_root_directory: "/opt/pki"
            domain: "example.com"
            certificate_subject_country_name: "US"
            certificate_subject_organization_name: "Example Corp"
            private_key_passphrase_random: true
          root:
            __parameters:
              name: "Example Root CA"
              private_key_encrypted: true
              private_key_size: 4096
              certificate_term: 7300  # 20 years
            intermediate:
              __parameters:
                name: "Example Intermediate CA"
                default: true  # Default CA for issuing certificates
                private_key_encrypted: true
                certificate_term: 3650  # 10 years

    - name: Issue a server certificate
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_ca_cascade }}"
        ca_nickname: "intermediate"
        certificate_parameters:
          nickname: "web-server"
          certificate_type: "SERVER"
          certificate_subject_common_name: "www.example.com"
          certificate_subject_alternative_names:
            - "DNS:example.com"
            - "DNS:*.example.com"
            - "IP:192.168.1.100"
          certificate_term: 365
```

## 📦 Installation

### Prerequisites

```bash
# System packages (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y python3-pip python3-cryptography

# System packages (RHEL/CentOS/Fedora)
sudo dnf install -y python3-pip python3-cryptography

# Python dependencies
pip3 install cryptography>=3.0 ansible-core>=2.9
```

### Install Collection

#### From Ansible Galaxy (Recommended)

```bash
ansible-galaxy collection install khmarochos.pki
```

#### From Source

```bash
# Clone the repository
git clone https://github.com/khmarochos/khmarochos.pki.git
cd khmarochos.pki

# Build the collection
ansible-galaxy collection build collections/ansible_collections/khmarochos/pki/

# Install the collection
ansible-galaxy collection install khmarochos-pki-*.tar.gz
```

#### Using requirements.yml

```yaml
---
collections:
  - name: khmarochos.pki
    version: ">=0.0.3"
```

Then install with:
```bash
ansible-galaxy collection install -r requirements.yml
```

## 🏗️ Core Concepts

### Certificate Authority Cascade

The collection uses a hierarchical "cascade" model for organizing CAs. Each level is nested within its parent:

```yaml
pki_ca_cascade:
  root:                           # Root Certificate Authority
    __parameters:
      # Root CA configuration
    intermediate:                 # Intermediate CA (child of root)
      __parameters:
        # Intermediate CA configuration
      web:                       # Web services CA (child of intermediate)
        __parameters:
          # Web CA configuration
      vpn:                       # VPN services CA (child of intermediate)
        __parameters:
          # VPN CA configuration
    backup:                      # Backup CA (child of root)
      __parameters:
        # Backup CA configuration
```

### Configuration Structure

All PKI configuration uses a nested dictionary structure with special keys:

- `__propagated`: Global parameters inherited by all CAs
- `__parameters`: CA-specific parameters
- Variable interpolation: Use `${variable_name}` syntax

### Certificate Types

The collection supports four certificate types:

1. **SERVER**: TLS server certificates (web servers, API endpoints)
2. **CLIENT**: Client authentication certificates (users, services)
3. **SERVER_CLIENT**: Dual-purpose certificates
4. **NONE**: Custom certificates with manual extension configuration

## 📚 Modules Reference

### init_pki

Initialize and manage PKI infrastructure with hierarchical CA cascades.

**Key Features:**
- Creates complete directory structure with secure permissions
- Generates CA private keys and self-signed certificates
- Supports complex multi-level CA hierarchies
- Handles both initial setup and updates

**Parameters:**

- `pki_ca_cascade` (required): Complete PKI configuration structure
- `load_if_exists` (optional, default: true): Load existing PKI components
- `save_if_needed` (optional, default: true): Save new components to disk
- `save_forced` (optional, default: false): Force regeneration of all components

**Example:**
```yaml
- name: Initialize enterprise PKI
  khmarochos.pki.init_pki:
    pki_ca_cascade:
      __propagated:
        global_root_directory: "/etc/pki/enterprise"
        domain: "corp.example.com"
        certificate_subject_country_name: "US"
        certificate_subject_state_or_province_name: "California"
        certificate_subject_locality_name: "San Francisco"
        certificate_subject_organization_name: "Example Corporation"
        certificate_subject_organizational_unit_name: "IT Security"
        private_key_algorithm: "RSA"
        private_key_passphrase_random: true
      root:
        __parameters:
          name: "Corporate Root Certificate Authority"
          private_key_encrypted: true
          private_key_size: 4096
          certificate_term: 7300
          certificate_digest_algorithm: "sha512"
```

### init_dictionary

Process and validate PKI configuration, creating lookup dictionaries for efficient CA management.

**Key Features:**
- Validates PKI configuration structure
- Creates CA nickname mappings
- Identifies default CAs
- Performs variable interpolation

**Parameters:**

- `pki_ca_cascade` (required): PKI configuration to process

**Example:**
```yaml
- name: Validate PKI configuration
  khmarochos.pki.init_dictionary:
    pki_ca_cascade: "{{ pki_config }}"
  register: pki_dict

- name: Display configuration summary
  debug:
    msg: |
      PKI Configuration:
      - Root Directory: {{ pki_dict.result.global_root_directory }}
      - Total CAs: {{ pki_dict.result.ca_count }}
      - Default CA: {{ pki_dict.result.default_ca_nickname }}
```

### issue_everything

Issue end-entity certificates with complete lifecycle management.

**Key Features:**
- Generates private keys, CSRs, and certificates in one operation
- Supports all certificate types (SERVER, CLIENT, SERVER_CLIENT)
- Handles Subject Alternative Names (SANs)
- Manages certificate chains automatically

**Parameters:**

- `pki_ca_cascade` (required): PKI configuration structure
- `ca_nickname` (required): Issuing CA nickname
- `certificate_parameters` (required): Certificate specification

**Certificate Parameters:**

- `nickname` (required): Unique identifier for the certificate
- `certificate_type` (required): SERVER, CLIENT, SERVER_CLIENT, or NONE
- `certificate_subject_common_name` (required): Primary certificate identifier (CN)
- `certificate_subject_alternative_names` (optional, default: []): List of SANs
- `certificate_term` (optional, default: CA default): Validity period in days
- `private_key_encrypted` (optional, default: false): Encrypt the private key
- `private_key_size` (optional, default: 2048): Key size in bits

**Example:**
```yaml
- name: Issue web server certificate
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_ca_cascade }}"
    ca_nickname: "web"
    certificate_parameters:
      nickname: "api-gateway"
      certificate_type: "SERVER"
      certificate_subject_common_name: "api.example.com"
      certificate_subject_alternative_names:
        - "DNS:api.example.com"
        - "DNS:api-v1.example.com"
        - "DNS:api-v2.example.com"
        - "IP:10.0.1.100"
      certificate_term: 90  # Short-lived for security
      private_key_encrypted: true
      private_key_size: 2048
```

## 💡 Usage Examples

### Multi-Environment PKI

Deploy separate PKI hierarchies for different environments:

```yaml
---
- name: Deploy Multi-Environment PKI
  hosts: localhost
  vars:
    environments:
      - name: production
        domain: "prod.example.com"
        root_term: 7300
        intermediate_term: 3650
        cert_term: 365
      - name: staging
        domain: "stage.example.com"
        root_term: 3650
        intermediate_term: 1825
        cert_term: 90
      - name: development
        domain: "dev.example.com"
        root_term: 1825
        intermediate_term: 365
        cert_term: 30

  tasks:
    - name: Initialize PKI for each environment
      khmarochos.pki.init_pki:
        pki_ca_cascade:
          __propagated:
            global_root_directory: "/opt/pki/{{ item.name }}"
            domain: "{{ item.domain }}"
            certificate_subject_country_name: "US"
            certificate_subject_organization_name: "Example Corp"
            certificate_subject_organizational_unit_name: "{{ item.name | title }} Environment"
            private_key_passphrase_random: true
          root:
            __parameters:
              name: "{{ item.name | title }} Root CA"
              private_key_encrypted: true
              private_key_size: 4096
              certificate_term: "{{ item.root_term }}"
            intermediate:
              __parameters:
                name: "{{ item.name | title }} Intermediate CA"
                default: true
                private_key_encrypted: true
                certificate_term: "{{ item.intermediate_term }}"
      loop: "{{ environments }}"
```

### Kubernetes TLS Secrets

Generate certificates and create Kubernetes secrets:

```yaml
---
- name: Create Kubernetes TLS Secrets
  hosts: localhost
  vars:
    namespace: "production"
    services:
      - name: "nginx-ingress"
        common_name: "*.apps.example.com"
        sans:
          - "DNS:apps.example.com"
          - "DNS:*.apps.example.com"
      - name: "api-gateway"
        common_name: "api.example.com"
        sans:
          - "DNS:api.example.com"
          - "DNS:api-internal.example.com"

  tasks:
    - name: Issue certificates for services
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_ca_cascade }}"
        ca_nickname: "intermediate"
        certificate_parameters:
          nickname: "{{ item.name }}"
          certificate_type: "SERVER"
          certificate_subject_common_name: "{{ item.common_name }}"
          certificate_subject_alternative_names: "{{ item.sans }}"
          certificate_term: 90
      loop: "{{ services }}"
      register: certificates

    - name: Create Kubernetes secrets
      kubernetes.core.k8s:
        state: present
        definition:
          apiVersion: v1
          kind: Secret
          metadata:
            name: "{{ item.item.name }}-tls"
            namespace: "{{ namespace }}"
          type: kubernetes.io/tls
          data:
            tls.crt: "{{ lookup('file', item.result.certificate.path) | b64encode }}"
            tls.key: "{{ lookup('file', item.result.private_key.path) | b64encode }}"
      loop: "{{ certificates.results }}"
```

### Client Certificate Management

Issue and manage client certificates for authentication:

```yaml
---
- name: Manage Client Certificates
  hosts: localhost
  vars:
    users:
      - username: "john.doe"
        email: "john.doe@example.com"
        department: "Engineering"
      - username: "jane.smith"
        email: "jane.smith@example.com"
        department: "Operations"

  tasks:
    - name: Create client CA if not exists
      khmarochos.pki.init_pki:
        pki_ca_cascade:
          __propagated:
            global_root_directory: "/opt/pki"
            certificate_subject_organization_name: "Example Corp"
          root:
            __parameters:
              name: "Root CA"
            client:
              __parameters:
                name: "Client Authentication CA"
                default: true
                certificate_term: 1825

    - name: Issue client certificates
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_ca_cascade }}"
        ca_nickname: "client"
        certificate_parameters:
          nickname: "{{ item.username }}"
          certificate_type: "CLIENT"
          certificate_subject_common_name: "{{ item.email }}"
          certificate_subject_organizational_unit_name: "{{ item.department }}"
          certificate_subject_alternative_names:
            - "email:{{ item.email }}"
          certificate_term: 365
          private_key_encrypted: true
      loop: "{{ users }}"

    - name: Create PKCS#12 bundles for users
      command: |
        openssl pkcs12 -export \
          -out "/opt/pki/client/bundles/{{ item.username }}.p12" \
          -inkey "/opt/pki/client/private/{{ item.username }}.key" \
          -in "/opt/pki/client/certs/{{ item.username }}.crt" \
          -certfile "/opt/pki/client/certs/CA/client.chain.crt" \
          -passout pass:changeme
      loop: "{{ users }}"
```

## 🏛️ PKI Architecture

### Directory Structure

The collection creates a standardized directory structure:

```
${global_root_directory}/
├── ${ca_nickname}/
│   ├── private/
│   │   ├── CA/
│   │   │   ├── ${ca_nickname}.key                    # CA private key
│   │   │   └── ${ca_nickname}.key_passphrase         # CA key passphrase
│   │   ├── ${certificate_nickname}.key               # Certificate private keys
│   │   └── ${certificate_nickname}.key_passphrase    # Certificate key passphrases
│   ├── certs/
│   │   ├── CA/
│   │   │   ├── ${ca_nickname}.crt                    # CA certificate
│   │   │   └── ${ca_nickname}.chain.crt              # CA certificate chain
│   │   ├── ${certificate_nickname}.crt               # Certificates
│   │   └── ${certificate_nickname}.chain.crt         # Certificate chains
│   ├── csr/
│   │   ├── CA/
│   │   │   └── ${ca_nickname}.csr                    # CA CSR
│   │   └── ${certificate_nickname}.csr               # Certificate CSRs
│   └── crl/
│       └── ${ca_nickname}.crl                        # CA CRL
```

### CA Hierarchy Design Patterns

#### Simple Two-Tier

Best for small to medium deployments:

```yaml
root:
  intermediate:    # Issues all certificates
```

#### Purpose-Based Separation

Separate CAs for different certificate purposes:

```yaml
root:
  server:         # Server certificates
  client:         # Client certificates
  code-signing:   # Code signing certificates
```

#### Environment-Based Separation

Isolated CAs for different environments:

```yaml
root:
  production:
    external:     # Internet-facing services
    internal:     # Internal services
  staging:
  development:
```

#### Geographic Distribution

CAs distributed by location:

```yaml
root:
  americas:
    us-east:
    us-west:
  europe:
    eu-west:
    eu-central:
  asia-pacific:
    ap-south:
    ap-northeast:
```

## ⚙️ Configuration Guide

### Global Parameters (__propagated)

These parameters are inherited by all CAs in the cascade:

```yaml
__propagated:
  # Required parameters
  global_root_directory: "/opt/pki"     # Base directory for all PKI files
  
  # Certificate subject defaults (inherited by all certificates)
  certificate_subject_country_name: "US"
  certificate_subject_state_or_province_name: "California"
  certificate_subject_locality_name: "San Francisco"
  certificate_subject_organization_name: "Example Corp"
  certificate_subject_organizational_unit_name: "IT"
  
  # Security parameters
  private_key_algorithm: "RSA"          # RSA or ECDSA
  private_key_size: 2048                # Key size in bits
  private_key_encrypted: false          # Encrypt private keys
  private_key_passphrase_random: true   # Generate random passphrases
  
  # Certificate parameters
  certificate_term: 365                 # Default validity in days
  certificate_digest_algorithm: "sha256" # Signature algorithm
  
  # Custom variables (accessible via ${variable_name})
  domain: "example.com"
  email_domain: "example.com"
  support_email: "pki-admin@${email_domain}"
```

### CA-Specific Parameters (__parameters)

Override global parameters for specific CAs:

```yaml
root:
  __parameters:
    name: "Root Certificate Authority"
    private_key_encrypted: true        # Always encrypt root CA keys
    private_key_size: 4096             # Stronger key for root
    certificate_term: 7300             # 20 years
    certificate_digest_algorithm: "sha512"
    
    # CA-specific extensions
    certificate_basic_constraints_ca: true
    certificate_basic_constraints_critical: true
    certificate_key_usage:
      - "keyCertSign"
      - "cRLSign"
    certificate_key_usage_critical: true
    
    # CRL distribution points
    certificate_crl_distribution_points:
      - "http://crl.${domain}/root-ca.crl"
      - "ldap://ldap.${domain}/cn=Root%20CA,ou=PKI,o=Example%20Corp,c=US"
```

### Variable Interpolation

Use `${variable_name}` syntax for dynamic values:

```yaml
__propagated:
  domain: "example.com"
  pki_email: "pki-admin@${domain}"
  crl_base_url: "http://crl.${domain}"

root:
  __parameters:
    name: "Root CA for ${domain}"
    certificate_crl_distribution_points:
      - "${crl_base_url}/root-ca.crl"
```

## 📋 Best Practices

### 1. Security Best Practices

#### Root CA Protection
- Always encrypt root CA private keys
- Store root CA offline when not in use
- Use hardware security modules (HSMs) for production
- Implement strong access controls

```yaml
root:
  __parameters:
    private_key_encrypted: true
    private_key_size: 4096
    certificate_term: 7300  # Long validity for offline CA
```

#### Key Management
- Use unique passphrases for each private key
- Rotate intermediate CA keys periodically
- Implement key escrow for recovery scenarios
- Never store passphrases in version control

```yaml
__propagated:
  private_key_passphrase_random: true
  private_key_passphrase_length: 32
```

#### Certificate Lifetimes
- Root CA: 15-20 years (offline storage)
- Intermediate CA: 5-10 years
- Server certificates: 90-365 days
- Client certificates: 365-730 days

### 2. Operational Best Practices

#### Monitoring and Alerting
```yaml
- name: Check certificate expiration
  shell: |
    find /opt/pki -name "*.crt" -type f | while read cert; do
      expiry=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2)
      days_left=$(( ($(date -d "$expiry" +%s) - $(date +%s)) / 86400 ))
      if [ $days_left -lt 30 ]; then
        echo "WARNING: $cert expires in $days_left days"
      fi
    done
  register: expiring_certs

- name: Alert on expiring certificates
  mail:
    to: "{{ pki_admin_email }}"
    subject: "PKI Certificate Expiration Warning"
    body: "{{ expiring_certs.stdout }}"
  when: expiring_certs.stdout != ""
```

#### Backup and Recovery
```yaml
- name: Backup PKI infrastructure
  archive:
    path: "{{ global_root_directory }}"
    dest: "/backup/pki-{{ ansible_date_time.epoch }}.tar.gz"
    format: gz
    mode: '0600'

- name: Encrypt backup with GPG
  shell: |
    gpg --encrypt --recipient {{ backup_key_id }} \
        /backup/pki-{{ ansible_date_time.epoch }}.tar.gz
  
- name: Remove unencrypted backup
  file:
    path: "/backup/pki-{{ ansible_date_time.epoch }}.tar.gz"
    state: absent
```

#### Audit Logging
```yaml
- name: Configure PKI audit logging
  blockinfile:
    path: /etc/rsyslog.d/pki-audit.conf
    block: |
      # Log all PKI operations
      :programname, isequal, "ansible-pki" /var/log/pki-audit.log
      & stop
    create: yes
    
- name: Setup log rotation
  copy:
    content: |
      /var/log/pki-audit.log {
          daily
          rotate 365
          compress
          delaycompress
          notifempty
          create 0640 root adm
      }
    dest: /etc/logrotate.d/pki-audit
```

### 3. Development Best Practices

#### Testing PKI Configurations
```yaml
- name: Validate PKI configuration
  khmarochos.pki.init_dictionary:
    pki_ca_cascade: "{{ pki_ca_cascade }}"
  check_mode: yes
  register: validation_result

- name: Ensure configuration is valid
  assert:
    that:
      - validation_result is succeeded
      - validation_result.result.ca_count > 0
    fail_msg: "PKI configuration validation failed"
```

#### Version Control
- Store PKI configuration in Git
- Never commit private keys or passphrases
- Use ansible-vault for sensitive variables
- Tag releases for configuration changes

```yaml
# vars/pki-config.yml
pki_ca_cascade:
  __propagated:
    global_root_directory: "{{ vault_pki_root_directory }}"
    # ... other configuration ...

# vars/vault.yml (encrypted with ansible-vault)
vault_pki_root_directory: "/opt/secure-pki"
vault_root_ca_passphrase: "super-secret-passphrase"
```

## 🔒 Security

### File Permissions

The collection enforces strict file permissions:

**Directory Permissions:**
- `private/`: Mode 700 - CA private key directory
- `private/CA/`: Mode 700 - CA private keys directory
- `certs/`: Mode 755 - Certificate directory
- `csr/`: Mode 755 - CSR directory
- `crl/`: Mode 755 - CRL directory

**File Permissions:**
- `*.key`: Mode 600 - Private key files
- `*.key_passphrase`: Mode 600 - Passphrase files
- `*.crt`: Mode 644 - Certificate files
- `*.csr`: Mode 644 - CSR files
- `*.crl`: Mode 644 - CRL files

### Security Hardening

#### SELinux Configuration
```bash
# Create custom SELinux policy for PKI
cat > pki_ansible.te << 'EOF'
module pki_ansible 1.0;

require {
    type ansible_t;
    type cert_t;
    class file { create read write unlink };
    class dir { create read write remove_name add_name };
}

allow ansible_t cert_t:file { create read write unlink };
allow ansible_t cert_t:dir { create read write remove_name add_name };
EOF

# Compile and install the policy
checkmodule -M -m -o pki_ansible.mod pki_ansible.te
semodule_package -o pki_ansible.pp -m pki_ansible.mod
semodule -i pki_ansible.pp
```

#### AppArmor Profile
```bash
# /etc/apparmor.d/usr.bin.ansible-pki
#include <tunables/global>

/usr/bin/ansible-playbook {
  #include <abstractions/base>
  #include <abstractions/python>
  
  /opt/pki/ r,
  /opt/pki/** rw,
  /etc/pki/** r,
  /usr/bin/openssl ix,
  
  # Deny network access except for localhost
  network inet stream,
  deny network inet6,
  deny network raw,
}
```

### Compliance Considerations

#### FIPS 140-2 Compliance
```yaml
__propagated:
  # FIPS-approved algorithms only
  private_key_algorithm: "RSA"
  private_key_size: 2048  # Minimum for FIPS
  certificate_digest_algorithm: "sha256"
  
  # Disable non-FIPS algorithms
  allowed_signature_algorithms:
    - "sha256WithRSAEncryption"
    - "sha384WithRSAEncryption"
    - "sha512WithRSAEncryption"
```

#### PCI-DSS Requirements
- Minimum 2048-bit RSA keys
- SHA-256 or stronger signatures  
- Annual certificate rotation
- Encrypted key storage
- Audit logging enabled

## 🔧 Troubleshooting

### Common Issues

#### Permission Denied Errors
```bash
# Fix ownership and permissions
sudo chown -R ansible:ansible /opt/pki
find /opt/pki -type d -name private -exec chmod 700 {} \;
find /opt/pki -name "*.key" -exec chmod 600 {} \;
find /opt/pki -name "passphrase" -exec chmod 600 {} \;
```

#### Certificate Verification Failed
```bash
# Verify certificate chain
openssl verify -CAfile /opt/pki/root/certs/CA/root.crt \
    -untrusted /opt/pki/intermediate/certs/CA/intermediate.crt \
    /opt/pki/intermediate/certs/server.crt

# Check certificate details
openssl x509 -in /opt/pki/intermediate/certs/server.crt \
    -text -noout
```

#### Module Import Errors
```bash
# Ensure Python cryptography is installed
pip3 install --upgrade cryptography

# Verify Ansible can find the collection
ansible-galaxy collection list | grep khmarochos.pki

# Check collection path
ansible-config dump | grep COLLECTIONS_PATHS
```

### Debug Mode

Enable verbose logging for troubleshooting:

```yaml
- name: Initialize PKI with debug output
  khmarochos.pki.init_pki:
    pki_ca_cascade: "{{ pki_ca_cascade }}"
  environment:
    ANSIBLE_DEBUG: "1"
    ANSIBLE_VERBOSITY: "4"
  register: pki_result

- name: Display detailed results
  debug:
    var: pki_result
    verbosity: 2
```

### Health Checks

```yaml
---
- name: PKI Health Check Playbook
  hosts: localhost
  gather_facts: yes
  tasks:
    - name: Check PKI directory structure
      stat:
        path: "{{ item }}"
      loop:
        - "/opt/pki"
        - "/opt/pki/root/private/CA"
        - "/opt/pki/root/certs/CA"
      register: dir_checks

    - name: Verify CA certificates
      command: openssl x509 -noout -subject -issuer -dates -in {{ item }}
      loop:
        - "/opt/pki/root/certs/CA/root.crt"
        - "/opt/pki/intermediate/certs/CA/intermediate.crt"
      register: cert_checks
      changed_when: false

    - name: Check certificate expiration
      shell: |
        openssl x509 -checkend 2592000 -noout -in {{ item }}
      loop:
        - "/opt/pki/root/certs/CA/root.crt"
        - "/opt/pki/intermediate/certs/CA/intermediate.crt"
      register: expiry_checks
      changed_when: false
      failed_when: expiry_checks.rc != 0

    - name: Generate health report
      template:
        src: pki_health_report.j2
        dest: /tmp/pki_health_report_{{ ansible_date_time.epoch }}.txt
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/khmarochos/khmarochos.pki.git
cd khmarochos.pki

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest collections/ansible_collections/khmarochos/pki/tests/

# Run linters
ansible-lint collections/ansible_collections/khmarochos/pki/
flake8 collections/ansible_collections/khmarochos/pki/plugins/
```

### Code Style

- Follow [Ansible Best Practices](https://docs.ansible.com/ansible/latest/user_guide/playbooks_best_practices.html)
- Python code follows PEP 8
- YAML files use 2-space indentation
- All modules must have DOCUMENTATION, EXAMPLES, and RETURN sections

### Testing

All contributions must include tests:

```python
# tests/unit/modules/test_init_pki.py
import pytest
from ansible_collections.khmarochos.pki.plugins.modules import init_pki

def test_init_pki_basic():
    """Test basic PKI initialization."""
    module_args = {
        'pki_ca_cascade': {
            '__propagated': {
                'global_root_directory': '/tmp/test-pki',
                'certificate_subject_country_name': 'US',
                'certificate_subject_organization_name': 'Test Org'
            },
            'root': {
                '__parameters': {
                    'name': 'Test Root CA'
                }
            }
        }
    }
    # Test implementation...
```

## 📄 License

This collection is licensed under the [Apache License 2.0](LICENSE).

## 🙏 Acknowledgments

- The Ansible community for the excellent automation framework
- The Python cryptography library maintainers
- All contributors who have helped improve this collection

## 📞 Support

- **Documentation**: [https://khmarochos.github.io/pki](https://khmarochos.github.io/pki)
- **Issues**: [GitHub Issues](https://github.com/khmarochos/khmarochos.pki/issues)
- **Discussions**: [GitHub Discussions](https://github.com/khmarochos/khmarochos.pki/discussions)
- **Security**: Please report security issues to security@khmarochos.com

---

Made with ❤️ by the khmarochos.pki community