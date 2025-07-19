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
short_description: Initialize PKI infrastructure and CA cascades
description:
    - Sets up PKI infrastructure by creating certificate authority cascades.
    - Creates directory structures, generates private keys, and issues CA certificates.
    - Supports loading existing PKI structures and saving new ones.
version_added: "1.0.0"
options:
    pki_ca_cascade:
        description:
            - Configuration dictionary for the PKI CA cascade structure.
        required: true
        type: dict
    load_if_exists:
        description:
            - Whether to load existing PKI structures if they exist.
        required: false
        type: bool
        default: true
    save_if_needed:
        description:
            - Whether to save PKI structures when needed.
        required: false
        type: bool
        default: true
    save_forced:
        description:
            - Whether to force saving of PKI structures.
        required: false
        type: bool
        default: false
author:
    - Volodymyr Melnyk
'''

EXAMPLES = r'''
- name: Initialize PKI infrastructure
  khmarochos.pki.init_pki:
    pki_ca_cascade:
      global_root_directory: /etc/pki
      ca_cascade:
        - nickname: root-ca
          certificate_type: root_ca
        - nickname: intermediate-ca
          certificate_type: intermediate_ca
          issuer: root-ca
    load_if_exists: true
    save_if_needed: true
'''

RETURN = r'''
result:
    description: PKI cascade JSON structure with created components
    returned: always
    type: dict
    sample:
        ca_cascade:
          - nickname: root-ca
            certificate_type: root_ca
changed:
    description: Whether any changes were made to the PKI structure
    returned: always
    type: bool
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
