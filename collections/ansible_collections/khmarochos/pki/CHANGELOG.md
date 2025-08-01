# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.5] - 2025-01-31

### Added
- Integrated bash-helpers library as a git submodule for improved logging
- Lifecycle management for automatic cleanup of temporary resources
- Docker build validation to ensure bash-helpers submodule is present
- DOCKER_BUILD.md documentation for proper build process

### Changed
- Refactored docker-entrypoint.sh to use bash-helpers logging functions
- Updated .dockerignore to properly include scripts/lib directory
- Enhanced error handling with die() function from bash-helpers

### Fixed
- Fixed playbook_simple.yaml syntax error (missing task list item marker)

## [0.0.4] - 2025-01-30

### Added
- Environment variable support for configuration file paths
  - `CA_TREE_FILE` - Override CA hierarchy configuration file path
  - `CERTIFICATES_FILE` - Override certificates configuration file path
  - `ARTIFACTS_DIRECTORY` - Override PKI artifacts directory path
- Parameterized playbook configuration using environment variables
- Enhanced Docker entrypoint script with ARTIFACTS_DIRECTORY support

### Changed
- Updated playbook.yaml to support dynamic configuration paths
- Modified docker-compose.yml to use new environment variable names
- Improved docker-entrypoint.sh to use ARTIFACTS_DIRECTORY for PKI state detection

### Documentation
- Added comprehensive Environment Variables section to README.md
- Updated Docker usage examples with new variable names
- Enhanced docker-compose documentation with current configuration

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