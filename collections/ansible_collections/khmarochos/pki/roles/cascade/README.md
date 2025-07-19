# Ansible Role: khmarochos.pki.cascade

## Description

The `cascade` role manages the deployment and configuration of PKI (Public Key Infrastructure) cascades. It installs required packages and sets up hierarchical Certificate Authority (CA) structures with proper certificate chains.

## Requirements

- Ansible >= 2.9
- Python >= 3.8
- Target system with package manager support (apt, yum, dnf)

## Role Variables

### Required Variables

- `pki_cascade_configuration`: Dictionary defining the PKI cascade structure

### Optional Variables

- `skip_packages`: (boolean, default: `false`) Skip package installation if set to `true`

### Example Configuration

```yaml
pki_cascade_configuration:
  global_root_directory: /opt/pki
  cascade:
    - nickname: root-ca
      type: root
      common_name: "Example Root CA"
      key_size: 4096
      validity_days: 7300
    - nickname: intermediate-ca
      type: intermediate
      parent: root-ca
      common_name: "Example Intermediate CA"
      key_size: 2048
      validity_days: 3650
    - nickname: server-ca
      type: intermediate
      parent: intermediate-ca
      common_name: "Example Server CA"
      key_size: 2048
      validity_days: 1825
```

## Dependencies

This role depends on the following Ansible modules from the khmarochos.pki collection:
- `khmarochos.pki.init_pki`

## Example Playbook

### Basic Usage

```yaml
---
- hosts: pki_servers
  become: yes
  roles:
    - role: khmarochos.pki.cascade
      vars:
        pki_cascade_configuration:
          global_root_directory: /opt/pki
          cascade:
            - nickname: root-ca
              type: root
              common_name: "Company Root CA"
              key_size: 4096
              validity_days: 7300
            - nickname: intermediate-ca
              type: intermediate
              parent: root-ca
              common_name: "Company Intermediate CA"
              key_size: 2048
              validity_days: 3650
```

### Advanced Usage with Custom Configuration

```yaml
---
- hosts: pki_infrastructure
  become: yes
  vars:
    pki_config:
      global_root_directory: /var/lib/pki
      cascade:
        - nickname: company-root
          type: root
          common_name: "ACME Corporation Root CA"
          country: US
          state: California
          locality: San Francisco
          organization: "ACME Corporation"
          organizational_unit: "IT Security"
          key_size: 4096
          validity_days: 7300
          key_usage:
            - key_cert_sign
            - crl_sign
        - nickname: server-intermediate
          type: intermediate
          parent: company-root
          common_name: "ACME Server Intermediate CA"
          country: US
          state: California
          locality: San Francisco
          organization: "ACME Corporation"
          organizational_unit: "Server Operations"
          key_size: 2048
          validity_days: 3650
        - nickname: client-intermediate
          type: intermediate
          parent: company-root
          common_name: "ACME Client Intermediate CA"
          country: US
          state: California
          locality: San Francisco
          organization: "ACME Corporation"
          organizational_unit: "Client Services"
          key_size: 2048
          validity_days: 3650

  tasks:
    - name: Deploy PKI cascade
      include_role:
        name: khmarochos.pki.cascade
      vars:
        pki_cascade_configuration: "{{ pki_config }}"
```

### Skip Package Installation

```yaml
---
- hosts: containerized_pki
  roles:
    - role: khmarochos.pki.cascade
      vars:
        skip_packages: true
        pki_cascade_configuration:
          global_root_directory: /app/pki
          cascade:
            - nickname: app-root
              type: root
              common_name: "Application Root CA"
```

## Supported Platforms

- **Ubuntu**: 18.04, 20.04, 22.04
- **CentOS**: 7, 8
- **RHEL**: 7, 8, 9
- **Rocky Linux**: 8, 9
- **AlmaLinux**: 8, 9

## Directory Structure Created

After successful execution, the role creates the following directory structure:

```
{global_root_directory}/
├── {ca_nickname_1}/
│   ├── private/CA/          # Private keys (600 permissions)
│   ├── certs/CA/           # Certificates and chains
│   ├── csr/CA/             # Certificate signing requests
│   └── crl/                # Certificate revocation lists
├── {ca_nickname_2}/
│   ├── private/CA/
│   ├── certs/CA/
│   ├── csr/CA/
│   └── crl/
└── ...
```

## Return Values

The role registers the following variables:

- `pki_cascade`: Contains the complete state of the PKI cascade after setup
  - `changed`: Boolean indicating if changes were made
  - `result`: Dictionary with detailed cascade information

## Security Considerations

- Private keys are stored with restrictive permissions (600)
- Passphrases are generated securely and stored encrypted
- Root CA private keys should be stored offline in production environments
- Regular backup of the PKI directory structure is recommended

## Troubleshooting

### Package Installation Issues

If package installation fails, you can:
1. Set `skip_packages: true` and install packages manually
2. Check the specific package installation tasks for your OS

### Permission Errors

Ensure the user running the playbook has sufficient privileges to:
- Create directories in the specified `global_root_directory`
- Set file permissions on private key files
- Install system packages (if not skipping packages)

### Certificate Chain Validation

The role automatically validates certificate chains. If validation fails:
1. Check the parent-child relationships in your cascade configuration
2. Verify that parent CAs exist before creating child CAs
3. Review the certificate validity periods

## License

Apache License 2.0

## Author Information

This role was created by Volodymyr Melnyk as part of the khmarochos.pki collection.

## Support

- Issues: https://github.com/khmarochos/khmarochos.pki/issues
- Documentation: https://github.com/khmarochos/khmarochos.pki/wiki