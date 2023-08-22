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

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.khmarochos.pki.plugins.module_utils.exceptions import PKICascadeError
from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade import PKICascade


ARGUMENT_SPEC = {
    'pki_ca_cascade': {'required': True, 'type': 'dict'}
}


def main():
    module = AnsibleModule(argument_spec=ARGUMENT_SPEC)

    pki_cascade = None

    try:
        pki_cascade = PKICascade(module.params['pki_ca_cascade'])
    except PKICascadeError as e:
        module.fail_json(msg=f"Can't traverse the CA cascade: {e}")
    except Exception as e:
        module.fail_json(msg=e.__str__())

    module.exit_json(changed=False, result=pki_cascade.pki_cascade_json())


if __name__ == '__main__':
    main()
