# Ansible Collection - khmarochos.pki

This Ansible collection provides comprehensive PKI (Public Key Infrastructure) management capabilities for creating and managing Certificate Authorities (CAs), issuing certificates, and generating Kubernetes secrets from PKI certificates.

## Features

- **Certificate Authority Management**: Create and manage hierarchical CA structures
- **Certificate Issuance**: Issue various types of certificates (Root CA, Intermediate CA, End-entity)
- **Private Key Management**: Generate and encrypt private keys with secure passphrases
- **Kubernetes Integration**: Generate K8s secrets from PKI certificates
- **Flexible Configuration**: Dynamic property management with string interpolation
- **Security First**: Proper file permissions and encrypted storage for sensitive materials

## Installation

Install the collection from Ansible Galaxy:

```bash
ansible-galaxy collection install khmarochos.pki
```

## Modules

- `khmarochos.pki.init_pki`: Initialize PKI infrastructure and CA cascades
- `khmarochos.pki.init_dictionary`: Set up PKI dictionary structures  
- `khmarochos.pki.issue_everything`: Bulk certificate issuance operations

## Roles

### khmarochos.pki.cascade

Manages the deployment and configuration of PKI cascades, including installation of required packages and setup of hierarchical Certificate Authority structures.

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
          global_root_directory: /opt/pki
          cascade:
            - nickname: root-ca
              type: root
              common_name: "Company Root CA"
            - nickname: intermediate-ca
              type: intermediate
              parent: root-ca
              common_name: "Company Intermediate CA"
```

## Plugins

- `khmarochos.pki.pki_dictionary`: Lookup plugin for PKI dictionary access

## Directory Structure

The PKI system organizes files in a structured hierarchy:
```
{global_root_directory}/{ca_nickname}/
├── private/CA/          # Private keys (restricted permissions)
├── certs/CA/           # Certificates and chains
├── csr/CA/             # Certificate signing requests
└── crl/                # Certificate revocation lists
```

## Example Usage

```yaml
- name: Initialize PKI cascade
  khmarochos.pki.init_pki:
    global_root_directory: /opt/pki
    cascade_config:
      - nickname: root-ca
        type: root
      - nickname: intermediate-ca
        type: intermediate
        parent: root-ca

- name: Issue certificates
  khmarochos.pki.issue_everything:
    global_root_directory: /opt/pki
    certificate_requests:
      - name: web-server
        ca: intermediate-ca
        common_name: example.com
```

## Requirements

- Python >= 3.8
- cryptography library
- Ansible >= 2.9

## License

Apache License 2.0

## Author Information

This collection was created by Volodymyr Melnyk.
