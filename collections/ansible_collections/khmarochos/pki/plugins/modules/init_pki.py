#!/usr/bin/python

# Copyright 2023 Volodymyr Melnyk
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

DOCUMENTATION = r'''
---
module: init_pki
short_description: Initialize and setup complete PKI infrastructure with hierarchical Certificate Authority cascades
description:
    - Foundation module for PKI infrastructure management that creates directory structures, generates private keys, and issues CA certificates.
    - Establishes complete certificate authority hierarchy according to configuration with support for complex multi-level CA structures.
    - Intelligently handles both fresh installations and updates to existing PKI structures with proper change tracking.
    - Creates all necessary directory structures with appropriate permissions for secure PKI operations.
    - Generates encrypted private keys with secure passphrases and issues corresponding CA certificates.
    - Supports hierarchical parameter inheritance and variable substitution for flexible configuration management.
version_added: "0.0.2"
options:
    pki_ca_cascade:
        description:
            - Complete PKI configuration structure defining CA hierarchy, global parameters, and CA-specific settings.
            - Must contain __propagated section with global parameters like global_root_directory and certificate subject fields.
            - Nested CA structure using hierarchical keys with __parameters sections for CA-specific configuration.
            - Supports variable substitution using ${variable_name} syntax for dynamic configuration.
        required: true
        type: dict
        elements: dict
    load_if_exists:
        description:
            - Load and integrate existing PKI certificates and keys if found in the file system.
            - When true, preserves existing PKI components and only generates missing ones.
            - When false, ignores existing files and may overwrite them if save_forced is also true.
        required: false
        type: bool
        default: true
    save_if_needed:
        description:
            - Save newly generated certificates and keys to disk when changes are detected.
            - When true, automatically persists new PKI components to the file system.
            - When false, generates PKI components in memory only without saving to disk.
        required: false
        type: bool
        default: true
    save_forced:
        description:
            - Force regeneration and saving of all PKI components, even if they already exist.
            - When true, overwrites existing certificates and keys with newly generated ones.
            - Useful for certificate renewal, key rotation, or recovering from corrupted PKI files.
            - Should be used with caution as it will replace all existing PKI materials.
        required: false
        type: bool
        default: false
notes:
    - This module creates directories with specific permissions (private directories mode 700, public directories mode 755).
    - Private keys are created with 600 permissions, certificates with 644 permissions.
    - When using encrypted private keys, passphrases are stored in separate files with 600 permissions.
    - The module tracks all changes and reports whether any modifications were made to the PKI infrastructure.
    - Root CAs should be generated offline and protected with strong passphrases for maximum security.
seealso:
    - module: khmarochos.pki.init_dictionary
    - module: khmarochos.pki.issue_everything
author:
    - Volodymyr Melnyk (@volodymyr-melnyk)
'''

EXAMPLES = r'''
# Basic PKI infrastructure setup
- name: Initialize basic PKI infrastructure
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
          name: "Root Certificate Authority (${domain})"
          private_key_encrypted: true
          private_key_size: 4096
          certificate_term: 3650
        intermediate:
          __parameters:
            default: true
            name: "Intermediate Certificate Authority (${domain})"
            private_key_encrypted: true
            private_key_size: 2048
            certificate_term: 1825
    load_if_exists: true
    save_if_needed: true
  register: pki_result

- name: Display PKI initialization results
  debug:
    msg: |
      PKI Infrastructure initialized:
      - Changed: {{ pki_result.changed }}
      - CAs created: {{ pki_result.result.ca_count | default(0) }}
      - Root directory: {{ pki_result.result.global_root_directory }}

# Enterprise multi-level PKI setup
- name: Initialize enterprise PKI with multiple environments
  khmarochos.pki.init_pki:
    pki_ca_cascade:
      __propagated:
        global_root_directory: "/etc/enterprise-pki"
        domain: "corp.example.com"
        certificate_subject_country_name: "US"
        certificate_subject_state_or_province_name: "California"
        certificate_subject_locality_name: "San Francisco"
        certificate_subject_organization_name: "Enterprise Corporation"
        certificate_subject_organizational_unit_name: "IT Security"
        certificate_subject_email_address: "pki-admin@corp.example.com"
        private_key_passphrase_random: true
        private_key_passphrase_length: 64
      root:
        __parameters:
          name: "Enterprise Root CA"
          private_key_encrypted: true
          private_key_size: 4096
          certificate_term: 7300  # 20 years
          strict: true
        production:
          __parameters:
            name: "Production Environment CA"
            default: true
            private_key_encrypted: true
            certificate_term: 1825  # 5 years
          web:
            __parameters:
              name: "Production Web Services CA"
              certificate_term: 365
          api:
            __parameters:
              name: "Production API Services CA"
              certificate_term: 180
        development:
          __parameters:
            name: "Development Environment CA"
            private_key_encrypted: false
            certificate_term: 90
        kubernetes:
          __parameters:
            name: "Kubernetes Cluster CA"
            private_key_encrypted: false
            certificate_term: 1095  # 3 years
    load_if_exists: true
    save_if_needed: true
  register: enterprise_pki

# Force regeneration of existing PKI (certificate renewal scenario)
- name: Force regenerate all PKI components
  khmarochos.pki.init_pki:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    load_if_exists: false
    save_if_needed: true
    save_forced: true
  register: renewed_pki
  tags: [certificate_renewal]

- name: Verify PKI renewal
  debug:
    msg: "PKI renewed successfully, all components regenerated"
  when: renewed_pki.changed

# Dry-run mode (generate without saving)
- name: Test PKI configuration without saving to disk
  khmarochos.pki.init_pki:
    pki_ca_cascade: "{{ test_pki_configuration }}"
    load_if_exists: true
    save_if_needed: false
    save_forced: false
  register: pki_test
  tags: [testing]

- name: Display test results
  debug:
    msg: |
      PKI test completed:
      - Configuration valid: {{ not pki_test.failed }}
      - Would create {{ pki_test.result.ca_count | default(0) }} CAs
      - Root directory: {{ pki_test.result.global_root_directory }}

# Error handling with detailed reporting
- name: Initialize PKI with error handling
  khmarochos.pki.init_pki:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
  register: pki_init
  failed_when: false

- name: Handle PKI initialization failure
  debug:
    msg: "PKI initialization failed: {{ pki_init.msg }}"
  when: pki_init.failed

- name: Handle PKI initialization success
  debug:
    msg: |
      PKI initialized successfully:
      - Changes made: {{ pki_init.changed }}
      - Components created: {{ pki_init.result.keys() | list }}
  when: not pki_init.failed
'''

RETURN = r'''
result:
    description: Complete PKI cascade structure with all generated components and metadata
    returned: always
    type: dict
    contains:
        global_root_directory:
            description: Base directory where all PKI files are stored
            type: str
            returned: always
        ca_count:
            description: Total number of CAs in the hierarchy
            type: int
            returned: always
        ca_hierarchy:
            description: Nested structure of all CAs with their properties
            type: dict
            returned: always
        certificates:
            description: Dictionary of all CA certificates with their file paths and properties
            type: dict
            returned: always
        private_keys:
            description: Dictionary of all private keys with encryption status and file paths
            type: dict
            returned: always
        passphrases:
            description: Dictionary of passphrases for encrypted private keys (values hidden)
            type: dict
            returned: when encrypted keys exist
        directory_structure:
            description: List of all created directories
            type: list
            elements: str
            returned: always
    sample:
        global_root_directory: "/opt/pki"
        ca_count: 2
        ca_hierarchy:
          root:
            name: "Root Certificate Authority"
            certificate_term: 3650
            private_key_encrypted: true
            private_key_size: 4096
            intermediate:
              name: "Intermediate Certificate Authority"
              certificate_term: 1825
              private_key_encrypted: true
              private_key_size: 2048
              default: true
        certificates:
          root:
            file: "/opt/pki/root/certs/CA/root.crt"
            chain_file: "/opt/pki/root/certs/CA/root.chain.crt"
            subject: "CN=Root Certificate Authority,O=Example Corp,C=US"
            valid_from: "2024-01-01T00:00:00Z"
            valid_until: "2034-01-01T00:00:00Z"
            serial_number: "1234567890ABCDEF"
          intermediate:
            file: "/opt/pki/intermediate/certs/CA/intermediate.crt"
            chain_file: "/opt/pki/intermediate/certs/CA/intermediate.chain.crt"
            subject: "CN=Intermediate Certificate Authority,O=Example Corp,C=US"
            valid_from: "2024-01-01T00:00:00Z"
            valid_until: "2029-01-01T00:00:00Z"
            serial_number: "FEDCBA0987654321"
        private_keys:
          root:
            file: "/opt/pki/root/private/CA/root.key"
            encrypted: true
            key_size: 4096
            algorithm: "RSA"
          intermediate:
            file: "/opt/pki/intermediate/private/CA/intermediate.key"
            encrypted: true
            key_size: 2048
            algorithm: "RSA"
        directory_structure:
          - "/opt/pki/root"
          - "/opt/pki/root/private"
          - "/opt/pki/root/private/CA"
          - "/opt/pki/root/certs"
          - "/opt/pki/root/certs/CA"
          - "/opt/pki/root/csr"
          - "/opt/pki/root/csr/CA"
          - "/opt/pki/root/crl"
          - "/opt/pki/intermediate"
          - "/opt/pki/intermediate/private"
          - "/opt/pki/intermediate/private/CA"
          - "/opt/pki/intermediate/certs"
          - "/opt/pki/intermediate/certs/CA"
          - "/opt/pki/intermediate/csr"
          - "/opt/pki/intermediate/csr/CA"
          - "/opt/pki/intermediate/crl"
changed:
    description: Whether any changes were made to the PKI infrastructure
    returned: always
    type: bool
    sample: true
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker \
    import ChangesStack
from ansible_collections.khmarochos.pki.plugins.module_utils.exceptions \
    import PKICascadeError
from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade \
    import PKICascade

ARGUMENT_SPEC = {
    'pki_ca_cascade': {'required': True, 'type': 'dict'},
    'load_if_exists': {'required': False, 'type': 'bool', 'default': True},
    'save_if_needed': {'required': False, 'type': 'bool', 'default': True},
    'save_forced': {'required': False, 'type': 'bool', 'default': False}
}


def main():
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC)

    changes_stack = ChangesStack()

    pki_cascade = None

    try:
        pki_cascade = PKICascade(
            pki_cascade_configuration=module.params['pki_ca_cascade'],
            changes_stack=changes_stack
        )
    except Exception as e:
        module.fail_json(msg=f"Can't traverse the CA cascade: {e.__str__()}")

    try:
        pki_cascade.setup(
            load_if_exists=module.params['load_if_exists'],
            save_if_needed=module.params['save_if_needed'],
            save_forced=module.params['save_forced']
        )
    except Exception as e:
        module.fail_json(msg=f"Can't set up the CA cascade: {e.__str__()}")

    module.exit_json(
        changed=bool(len(changes_stack) > 0),
        result=pki_cascade.pki_cascade_json()
    )


if __name__ == '__main__':
    main()
