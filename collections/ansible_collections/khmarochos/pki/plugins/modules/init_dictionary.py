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
module: init_dictionary
short_description: Initialize PKI configuration dictionary for efficient CA and certificate lookups
description:
    - Processes PKI cascade configuration and creates optimized lookup dictionaries.
    - Validates the hierarchical structure and parameter inheritance.
    - Creates CA nickname mappings and identifies default CAs for certificate issuance.
    - This module is primarily used internally by other modules but can be useful for custom automation scripts.
    - Always returns changed=false since it only processes data without modifying files.
version_added: "0.0.2"
options:
    pki_ca_cascade:
        description:
            - Complete PKI configuration structure defining CA hierarchy, global parameters, and CA-specific settings.
            - Must contain __propagated section with global parameters and nested CA structure.
            - Supports hierarchical inheritance and variable substitution.
        required: true
        type: dict
        elements: dict
notes:
    - This module does not create or modify any files, it only processes configuration data.
    - The module validates configuration structure and reports any issues during processing.
    - Use this module to validate PKI configurations before applying them with init_pki.
seealso:
    - module: khmarochos.pki.init_pki
    - module: khmarochos.pki.issue_everything
author:
    - Volodymyr Melnyk (@volodymyr-melnyk)
'''

EXAMPLES = r'''
# Basic PKI configuration validation
- name: Validate PKI configuration structure
  khmarochos.pki.init_dictionary:
    pki_ca_cascade:
      __propagated:
        global_root_directory: "/opt/pki"
        domain: "example.com"
        certificate_subject_country_name: "US"
        certificate_subject_organization_name: "Example Corp"
      root:
        __parameters:
          name: "Root Certificate Authority"
          private_key_encrypted: true
          certificate_term: 3650
        intermediate:
          __parameters:
            default: true
            name: "Intermediate CA"
            certificate_term: 1825
  register: pki_dict

# Use the dictionary result to display configuration information
- name: Show PKI configuration summary
  debug:
    msg: |
      PKI Configuration Summary:
      - Root Directory: {{ pki_dict.result.global_root_directory }}
      - Default CA: {{ pki_dict.result.default_ca_nickname }}
      - Total CAs: {{ pki_dict.result.ca_count }}

# Validate complex hierarchical structure
- name: Process enterprise PKI configuration
  khmarochos.pki.init_dictionary:
    pki_ca_cascade:
      __propagated:
        global_root_directory: "/etc/enterprise-pki"
        domain: "corp.example.com"
        certificate_subject_country_name: "US"
        certificate_subject_organization_name: "Enterprise Corp"
      root:
        __parameters:
          name: "Corporate Root CA"
          private_key_size: 4096
          certificate_term: 7300
        production:
          __parameters:
            name: "Production Environment CA"
            default: true
            certificate_term: 365
          web:
            __parameters:
              name: "Web Services CA"
  register: enterprise_pki

# Extract specific CA information
- name: Display all CA paths
  debug:
    msg: "CA {{ item.key }}: {{ item.value.paths.base }}"
  loop: "{{ enterprise_pki.result.all_cas | dict2items }}"

# Validate configuration before applying changes
- name: Pre-flight check for PKI configuration
  block:
    - name: Validate PKI structure
      khmarochos.pki.init_dictionary:
        pki_ca_cascade: "{{ proposed_pki_config }}"
      register: validation

    - name: Ensure minimum requirements are met
      assert:
        that:
          - validation.result.ca_count >= 2
          - validation.result.default_ca_nickname is defined
          - validation.result.global_root_directory | regex_search('^/')
        fail_msg: "PKI configuration does not meet minimum requirements"

    - name: Display validation results
      debug:
        msg: |
          Validation passed! Configuration summary:
          - CAs to create: {{ validation.result.ca_count }}
          - Default issuing CA: {{ validation.result.default_ca_nickname }}
          - Base directory: {{ validation.result.global_root_directory }}

# Use dictionary for dynamic certificate issuance
- name: Process PKI for multi-tenant environment
  khmarochos.pki.init_dictionary:
    pki_ca_cascade:
      __propagated:
        global_root_directory: "/opt/pki/multi-tenant"
        certificate_subject_organization_name: "Multi-Tenant Corp"
      root:
        __parameters:
          name: "Multi-Tenant Root CA"
        tenants:
          __parameters:
            name: "Tenant Management CA"
          tenant-a:
            __parameters:
              name: "Tenant A CA"
              default: true
          tenant-b:
            __parameters:
              name: "Tenant B CA"
  register: tenant_pki

- name: Show tenant-specific CAs
  debug:
    msg: "Found tenant CA: {{ item }}"
  when: "'tenant-' in item"
  loop: "{{ tenant_pki.result.all_cas.keys() | list }}"
              certificate_term: 90
          api:
            __parameters:
              name: "API Services CA"
              certificate_term: 30
        development:
          __parameters:
            name: "Development Environment CA"
            certificate_term: 30
  register: enterprise_pki

# Error handling example
- name: Validate PKI configuration with error handling
  khmarochos.pki.init_dictionary:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
  register: pki_validation
  failed_when: false

- name: Handle configuration errors
  debug:
    msg: "PKI configuration is invalid: {{ pki_validation.msg }}"
  when: pki_validation.failed
'''

RETURN = r'''
result:
    description: Processed PKI cascade dictionary structure with lookup mappings and configuration inheritance
    returned: always
    type: dict
    contains:
        global_root_directory:
            description: Base directory for all PKI files
            type: str
            returned: always
        default_ca_nickname:
            description: Nickname of the default CA for certificate issuance
            type: str
            returned: when default CA is configured
        ca_nicknames:
            description: List of all CA nicknames in the hierarchy
            type: list
            elements: str
            returned: always
        ca_hierarchy:
            description: Nested dictionary representing the CA hierarchy structure
            type: dict
            returned: always
        ca_count:
            description: Total number of CAs in the cascade
            type: int
            returned: always
        inheritance_chains:
            description: Parameter inheritance mapping for each CA
            type: dict
            returned: always
    sample:
        global_root_directory: "/opt/pki"
        default_ca_nickname: "intermediate"
        ca_nicknames:
          - "root"
          - "intermediate"
        ca_hierarchy:
          root:
            name: "Root Certificate Authority"
            certificate_term: 3650
            intermediate:
              name: "Intermediate CA"
              certificate_term: 1825
              default: true
        ca_count: 2
        inheritance_chains:
          root:
            domain: "example.com"
            global_root_directory: "/opt/pki"
          intermediate:
            domain: "example.com"
            global_root_directory: "/opt/pki"
            default: true
changed:
    description: Whether any changes were made (always false for this module)
    returned: always
    type: bool
    sample: false
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangesStack
from ansible_collections.khmarochos.pki.plugins.module_utils.exceptions import PKICascadeError
from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade import PKICascade


ARGUMENT_SPEC = {
    'pki_ca_cascade': {'required': True, 'type': 'dict'}
}


def main():

    module = AnsibleModule(argument_spec=ARGUMENT_SPEC)

    changes_stack = ChangesStack()

    pki_cascade = None

    try:
        pki_cascade = PKICascade(
            pki_cascade_configuration=module.params['pki_ca_cascade'],
            changes_stack=None
        )
    except PKICascadeError as e:
        module.fail_json(msg=f"Can't traverse the CA cascade: {e}")
    except Exception as e:
        module.fail_json(msg=e.__str__())

    module.exit_json(changed=bool(changes_stack.__len__() > 0), result=pki_cascade.pki_cascade_json())


if __name__ == '__main__':
    main()
