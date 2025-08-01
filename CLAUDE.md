# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the `khmarochos.pki` Ansible collection for PKI (Public Key Infrastructure) management. It provides modules, roles, and utilities for creating and managing Certificate Authorities (CAs), issuing certificates, and generating Kubernetes secrets from PKI certificates.

## Development Commands

### Testing
- Run unit tests: `python -m pytest collections/ansible_collections/khmarochos/pki/tests/unit/`
- Individual test files can be run directly with pytest

### Scripts
- Generate Kubernetes secrets from PKI certificates: `./scripts/make_secret.sh`

### Ansible Collection
- Collection is located in `collections/ansible_collections/khmarochos/pki/`
- Build collection: `ansible-galaxy collection build collections/ansible_collections/khmarochos/pki/`
- Install collection: `ansible-galaxy collection install collections/ansible_collections/khmarochos/pki/`

## Architecture

### Core Components

**PKI Management Classes** (`plugins/module_utils/`):
- `PKICA`: Main CA management class that handles certificate authority operations, certificate issuance, and file organization
- `PKICascade`: Manages hierarchical CA structures and certificate chains
- `CertificateBuilder`: Handles certificate creation and signing operations
- `PrivateKeyBuilder`: Manages private key generation and encryption
- `PassphraseBuilder`: Handles secure passphrase generation

**Ansible Modules** (`plugins/modules/`):
- `init_pki.py`: Initializes PKI infrastructure and CA cascades
- `init_dictionary.py`: Sets up PKI dictionary structures
- `issue_everything.py`: Bulk certificate issuance operations

**Support Classes**:
- `FlexiClass`: Provides dynamic property management with interpolation
- `ChangeTracker`: Tracks changes for Ansible's changed status
- `Certificate`, `CertificateSigningRequest`, `PrivateKey`, `Passphrase`: Core PKI object representations

### Directory Structure

The PKI system organizes files in a structured hierarchy:
```
{global_root_directory}/{ca_nickname}/
├── private/CA/          # Private keys (restricted permissions)
├── certs/CA/           # Certificates and chains
├── csr/CA/             # Certificate signing requests
└── crl/                # Certificate revocation lists
```

### Key Design Patterns

- **Builder Pattern**: Used extensively for creating PKI objects with validation
- **Property-based Configuration**: FlexiClass enables dynamic property management with string interpolation
- **Change Tracking**: All operations track changes for Ansible integration
- **File-based Storage**: All PKI objects are persisted to files with proper permissions

### Certificate Types

The system supports different certificate types via `CertificateTypes` enum:
- Root CA certificates
- Intermediate CA certificates  
- End-entity certificates with various purposes

### Security Features

- Encrypted private keys with passphrase management
- Proper file permissions for sensitive materials
- Secure random passphrase generation
- Certificate chain validation