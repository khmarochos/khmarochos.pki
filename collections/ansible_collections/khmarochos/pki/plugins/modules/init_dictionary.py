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
short_description: Initialize PKI dictionary structures
description:
    - Creates and validates PKI dictionary structures for certificate authority cascades.
    - This module parses the PKI cascade configuration and returns the resulting dictionary structure.
version_added: "1.0.0"
options:
    pki_ca_cascade:
        description:
            - Configuration dictionary for the PKI CA cascade structure.
        required: true
        type: dict
author:
    - Volodymyr Melnyk
'''

EXAMPLES = r'''
- name: Initialize PKI dictionary
  khmarochos.pki.init_dictionary:
    pki_ca_cascade:
      global_root_directory: /etc/pki
      ca_cascade:
        - nickname: root-ca
          certificate_type: root_ca
'''

RETURN = r'''
result:
    description: PKI cascade JSON structure
    returned: always
    type: dict
    sample:
        ca_cascade:
          - nickname: root-ca
            certificate_type: root_ca
changed:
    description: Whether any changes were made
    returned: always
    type: bool
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
