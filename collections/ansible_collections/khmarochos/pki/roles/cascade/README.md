# Ansible Role: khmarochos.pki.cascade

The `cascade` role provides a complete solution for deploying and managing hierarchical PKI (Public Key Infrastructure) environments. It handles everything from system package installation to complex multi-tier Certificate Authority structures.

## Overview

This role automates:
- Installation of required cryptography packages
- Creation of hierarchical CA structures
- Certificate chain management
- Security best practices enforcement
- Idempotent PKI operations

## Requirements

### System Requirements
- **Operating Systems**: 
  - Ubuntu 18.04+ / Debian 9+
  - RHEL/CentOS 7+ / Fedora 30+
  - Amazon Linux 2
- **Python**: 3.8 or higher
- **Ansible**: 2.9 or higher
- **Privileges**: Sudo access for package installation

### Python Dependencies
- `cryptography >= 3.0`
- `pyOpenSSL >= 19.0.0` (optional, for validation)

## Role Variables

### Required Variables

#### pki_cascade_configuration
**Type**: Dictionary  
**Description**: Complete PKI cascade configuration structure

```yaml
pki_cascade_configuration:
  __propagated:
    # Global settings inherited by all CAs
    global_root_directory: "/opt/pki"
    domain: "example.com"
    certificate_subject_country_name: "US"
    certificate_subject_state_or_province_name: "California"
    certificate_subject_locality_name: "San Francisco"
    certificate_subject_organization_name: "Example Corporation"
    certificate_subject_organizational_unit_name: "IT Security"
    private_key_algorithm: "RSA"
    private_key_passphrase_random: true
    certificate_digest_algorithm: "sha256"
  
  # CA hierarchy definition
  root:
    __parameters:
      name: "Example Root Certificate Authority"
      private_key_encrypted: true
      private_key_size: 4096
      certificate_term: 7300  # 20 years
      certificate_digest_algorithm: "sha512"
  
    intermediate:
      __parameters:
        name: "Example Intermediate CA"
      default: true  # Default CA for certificate issuance
      private_key_encrypted: true
      certificate_term: 3650  # 10 years
```

### Optional Variables

#### skip_packages
**Type**: Boolean  
**Default**: `false`  
**Description**: Skip system package installation (useful in containers or when packages are pre-installed)

#### pki_packages
**Type**: List  
**Default**: Auto-detected based on OS  
**Description**: Override default package list

```yaml
pki_packages:
  - python3-cryptography
  - openssl
  - ca-certificates
```

#### pki_cascade_load_if_exists
**Type**: Boolean  
**Default**: `true`  
**Description**: Load existing PKI components instead of regenerating

#### pki_cascade_save_if_needed
**Type**: Boolean  
**Default**: `true`  
**Description**: Save newly generated PKI components to disk

#### pki_cascade_save_forced
**Type**: Boolean  
**Default**: `false`  
**Description**: Force regeneration of all PKI components (CAUTION: This will overwrite existing certificates)

#### pki_cascade_backup_before_changes
**Type**: Boolean  
**Default**: `true`  
**Description**: Create backup before making changes to existing PKI

#### pki_cascade_backup_directory
**Type**: String  
**Default**: `/var/backups/pki`  
**Description**: Directory for PKI backups

## Dependencies

### Collection Dependencies
- `khmarochos.pki` collection modules:
  - `init_pki`: For PKI infrastructure initialization
  - `init_dictionary`: For configuration validation
  - `issue_everything`: For certificate issuance (if needed)

### Role Dependencies
None - this is a standalone role

## Example Playbooks

### Basic Two-Tier PKI
```yaml
---
- name: Deploy Basic PKI Infrastructure
  hosts: pki_servers
  become: yes
  roles:
    - role: khmarochos.pki.cascade
      vars:
        pki_cascade_configuration:
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
              certificate_term: 7300
            intermediate:
              __parameters:
                name: "Example Intermediate CA"
              default: true
              private_key_encrypted: true
              certificate_term: 3650
```

### Enterprise Multi-Tier PKI
```yaml
---
- name: Deploy Enterprise PKI Infrastructure
  hosts: pki_servers
  become: yes
  roles:
    - role: khmarochos.pki.cascade
      vars:
        pki_cascade_configuration:
          __propagated:
            global_root_directory: "/etc/pki/enterprise"
            domain: "corp.example.com"
            certificate_subject_country_name: "US"
            certificate_subject_state_or_province_name: "California"
            certificate_subject_locality_name: "San Francisco"
            certificate_subject_organization_name: "Example Corporation"
            certificate_subject_organizational_unit_name: "Information Security"
            private_key_algorithm: "RSA"
            private_key_passphrase_random: true
            certificate_digest_algorithm: "sha256"
            # CRL and OCSP configuration
            crl_distribution_url: "http://crl.corp.example.com"
            ocsp_responder_url: "http://ocsp.corp.example.com"
          
          # Offline root CA
          root:
            __parameters:
              name: "Example Corp Root CA"
              private_key_encrypted: true
              private_key_size: 4096
              certificate_term: 7300
              certificate_digest_algorithm: "sha512"
              certificate_crl_distribution_points:
                - "${crl_distribution_url}/root-ca.crl"
          
          # Policy CA tier
            policy:
              __parameters:
                name: "Example Corp Policy CA"
                private_key_encrypted: true
                certificate_term: 3650
                certificate_crl_distribution_points:
                  - "${crl_distribution_url}/policy-ca.crl"
              
              # Issuing CA tier
              external:
                __parameters:
                  name: "External Services CA"
                  default: true
                  certificate_term: 1825
                  certificate_crl_distribution_points:
                    - "${crl_distribution_url}/external-ca.crl"
              
              internal:
                __parameters:
                  name: "Internal Services CA"
                  certificate_term: 1825
                  certificate_crl_distribution_points:
                    - "${crl_distribution_url}/internal-ca.crl"
              
              users:
                __parameters:
                  name: "User Authentication CA"
                  certificate_term: 1825
                  certificate_crl_distribution_points:
                    - "${crl_distribution_url}/users-ca.crl"
```

### Development Environment PKI
```yaml
---
- name: Deploy Development PKI
  hosts: localhost
  connection: local
  become: yes
  roles:
    - role: khmarochos.pki.cascade
      vars:
        skip_packages: true  # Assume packages are installed
        pki_cascade_backup_before_changes: false  # No backups in dev
        pki_cascade_configuration:
          __propagated:
            global_root_directory: "/tmp/dev-pki"
            certificate_subject_organization_name: "Development"
            private_key_passphrase_random: false  # No encryption in dev
            private_key_encrypted: false
          root:
            __parameters:
              name: "Dev Root CA"
              certificate_term: 365  # Short validity for dev
            apps:
              __parameters:
                name: "Dev Apps CA"
                default: true
                certificate_term: 90
```

### Container-Based PKI
```yaml
---
- name: Deploy PKI in Container
  hosts: pki_containers
  roles:
    - role: khmarochos.pki.cascade
      vars:
        skip_packages: true  # Packages installed in Dockerfile
        pki_cascade_configuration:
          __propagated:
            global_root_directory: "/pki"
            certificate_subject_organization_name: "Container Corp"
            # Environment variable interpolation
            domain: "${DOMAIN_NAME}"
            private_key_passphrase: "${PKI_PASSPHRASE}"
          root:
            __parameters:
              name: "Container Root CA"
              private_key_encrypted: true
              certificate_term: 3650
            services:
              __parameters:
                name: "Container Services CA"
                default: true
                certificate_term: 365
```

## Advanced Usage

### Pre and Post Tasks

```yaml
---
- name: PKI Deployment with Hooks
  hosts: pki_servers
  become: yes
  
  pre_tasks:
    - name: Ensure backup directory exists
      file:
        path: /secure/pki-backups
        state: directory
        mode: '0700'
        owner: root
        group: root
    
    - name: Check disk space
      shell: df -h /opt | tail -1 | awk '{print $5}' | sed 's/%//'
      register: disk_usage
      changed_when: false
      failed_when: disk_usage.stdout|int > 90
  
  roles:
    - role: khmarochos.pki.cascade
      vars:
        pki_cascade_backup_directory: /secure/pki-backups
        pki_cascade_configuration: "{{ pki_config }}"
  
  post_tasks:
    - name: Set SELinux context for PKI files
      command: restorecon -R /opt/pki
      when: ansible_selinux.status == "enabled"
    
    - name: Export CA certificates for distribution
      fetch:
        src: "{{ item }}"
        dest: ./ca-certificates/
        flat: yes
      loop:
        - /opt/pki/root/certs/CA/root.crt
        - /opt/pki/intermediate/certs/CA/intermediate.crt
```

### Role in a Larger Deployment

```yaml
---
- name: Complete Infrastructure Deployment
  hosts: all
  become: yes
  
  tasks:
    - name: Deploy PKI infrastructure
      include_role:
        name: khmarochos.pki.cascade
      vars:
        pki_cascade_configuration: "{{ pki_config }}"
      when: inventory_hostname in groups['pki_servers']
    
    - name: Distribute CA certificates
      copy:
        src: "{{ item }}"
        dest: /etc/pki/ca-trust/source/anchors/
        mode: '0644'
      loop:
        - ca-certificates/ca.crt
        - ca-certificates/intermediate-ca.crt
      when: inventory_hostname not in groups['pki_servers']
      notify: update ca trust
    
    - name: Issue server certificates
      khmarochos.pki.issue_everything:
        pki_ca_cascade: "{{ pki_config }}"
        ca_nickname: "intermediate"
        certificate_parameters:
          nickname: "{{ inventory_hostname }}"
          certificate_type: "SERVER"
          certificate_subject_common_name: "{{ inventory_hostname }}.{{ domain }}"
          certificate_term: 365
      delegate_to: "{{ groups['pki_servers'][0] }}"
      when: inventory_hostname in groups['web_servers']
  
  handlers:
    - name: update ca trust
      command: update-ca-trust
```

## Security Considerations

### File Permissions
The role automatically sets secure file permissions:
- Private directories: `0700`
- Private keys: `0600`
- Public directories: `0755`
- Certificates: `0644`

### Best Practices Enforced
1. **Encrypted Private Keys**: Root and intermediate CA keys are encrypted by default
2. **Strong Key Sizes**: Minimum 2048-bit RSA keys, 4096-bit recommended for root CAs
3. **Secure Passphrases**: Random 32+ character passphrases generated automatically
4. **Proper Certificate Chains**: Complete chains are automatically maintained
5. **Backup Before Changes**: Automatic backups before modifications

### Compliance Features
- Supports custom certificate extensions for compliance requirements
- Configurable key algorithms and sizes for FIPS compliance
- CRL distribution points for revocation support
- OCSP responder URLs for real-time validation

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
TASK [khmarochos.pki.cascade : Initialize PKI cascade] ***
fatal: [localhost]: FAILED! => {"msg": "Permission denied: '/opt/pki'"}
```
**Solution**: Ensure the role runs with `become: yes` or proper permissions

#### Package Installation Failures
```bash
TASK [khmarochos.pki.cascade : Install required packages] ***
fatal: [localhost]: FAILED! => {"msg": "No package matching 'python3-cryptography' found"}
```
**Solution**: Update package cache or use `skip_packages: true` with manual installation

#### Existing PKI Conflicts
```bash
TASK [khmarochos.pki.cascade : Initialize PKI cascade] ***
fatal: [localhost]: FAILED! => {"msg": "CA already exists and save_forced is False"}
```
**Solution**: Either set `pki_cascade_save_forced: true` (CAUTION) or remove existing PKI

### Debug Mode
Enable verbose output for troubleshooting:
```yaml
- name: Deploy PKI with Debug
  hosts: pki_servers
  roles:
    - role: khmarochos.pki.cascade
      vars:
        pki_cascade_configuration: "{{ pki_config }}"
  environment:
    ANSIBLE_DEBUG: "1"
```

### Validation Commands
After deployment, validate the PKI:
```bash
# Check CA certificate
openssl x509 -in /opt/pki/root/certs/CA/ca.crt -text -noout

# Verify certificate chain
openssl verify -CAfile /opt/pki/root/certs/CA/root.crt \
  /opt/pki/intermediate/certs/CA/intermediate.crt

# List all certificates
find /opt/pki -name "*.crt" -type f -exec echo {} \; \
  -exec openssl x509 -subject -issuer -dates -noout -in {} \; -exec echo \;
```

## License

Apache License 2.0

## Author Information

This role was created by Volodymyr Melnyk for the khmarochos.pki collection.

## Contributing

Contributions are welcome! Please submit pull requests to the [khmarochos.pki repository](https://github.com/khmarochos/khmarochos.pki).

## Support

- GitHub Issues: [https://github.com/khmarochos/khmarochos.pki/issues](https://github.com/khmarochos/khmarochos.pki/issues)
- Documentation: [https://khmarochos.github.io/pki](https://khmarochos.github.io/pki)
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