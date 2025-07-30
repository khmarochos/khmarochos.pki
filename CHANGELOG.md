# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [0.0.3] - 2025-01-28

### Fixed
- Corrected import error in khmarochos.pki modules
- Fixed module path references for proper Ansible collection structure
- Resolved circular import issues in PKI classes

### Changed
- Reorganized imports to use absolute paths within the collection
- Updated all module imports to reference khmarochos.pki namespace correctly

## [0.0.2] - 2025-01-21

### Added
- Comprehensive documentation enhancements with detailed installation, configuration, and usage examples
- PKI state management tools for monitoring and comparing PKI infrastructure over time
- Docker integration with complete containerization support
- Advanced configuration examples for multi-environment and geographic distribution setups
- Detailed troubleshooting guide with common issues and solutions
- Best practices section for security guidelines and performance optimization
- Migration guide from other PKI tools
- Complete module documentation with parameter tables and use cases

### Enhanced
- README.md significantly expanded with detailed technical documentation
- Module documentation strings updated with comprehensive parameter descriptions
- Configuration inheritance rules and variable substitution examples
- Kubernetes integration examples with secret generation

### Fixed
- Version consistency across all module documentation
- Documentation structure and formatting improvements

## [0.0.1] - 2025-01-15

### Added
- Initial release of the Khmarochos PKI Collection
- Core modules: init_pki, init_dictionary, issue_everything
- Basic PKI infrastructure management capabilities
- Certificate Authority cascade support
- Private key and certificate generation
- Kubernetes secret generation script
- Basic Docker containerization
- Initial documentation and examples

### Features
- Hierarchical Certificate Authority management
- Flexible certificate issuance for server, client, and combined certificates
- Secure key management with optional encryption and passphrase management
- Ansible native integration with change tracking
- File-based storage with organized directory structure