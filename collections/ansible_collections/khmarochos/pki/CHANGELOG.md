# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1] - 2025-07-19

### Added
- Initial release of khmarochos.pki collection
- PKI management modules: `init_pki`, `init_dictionary`, `issue_everything`
- Core PKI utilities: PKICA, PKICascade, CertificateBuilder, PrivateKeyBuilder, PassphraseBuilder
- Support for hierarchical CA structures and certificate chains
- Kubernetes secret generation from PKI certificates
- Comprehensive unit test suite
- Role for PKI cascade management
- PKI dictionary lookup plugin

### Features
- Certificate Authority creation and management
- Certificate issuance with various types (Root CA, Intermediate CA, End-entity)
- Private key generation with encryption support
- Secure passphrase generation
- File-based PKI storage with proper permissions
- Change tracking for Ansible integration