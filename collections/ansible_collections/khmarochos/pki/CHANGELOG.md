# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] - 2025-07-21

### Changed
- Completely rewritten and enhanced collection-level README.md with comprehensive documentation
- Significantly improved module documentation with detailed parameter descriptions and extensive examples
- Enhanced DOCUMENTATION strings for all modules (init_pki, init_dictionary, issue_everything)
- Added comprehensive EXAMPLES sections with real-world scenarios including enterprise PKI, Kubernetes integration, and certificate renewal
- Improved RETURN value documentation with detailed field descriptions and sample data structures
- Added professional Ansible module documentation format following official standards

### Added
- Table of Contents and navigation structure in README.md
- Quick Start Guide with step-by-step examples
- Configuration Structure Guide explaining hierarchical PKI system
- Security Considerations section with best practices
- Multiple practical examples for each module covering various use cases
- Error handling patterns and conditional logic examples
- Cross-references between modules using seealso sections

### Documentation
- Enhanced module parameter descriptions with use cases and recommendations
- Added comprehensive suboptions documentation for certificate_parameters
- Included bulk certificate issuance examples and error handling patterns
- Added examples for Kubernetes API server certificates and enterprise scenarios
- Improved formatting and consistency across all documentation files

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