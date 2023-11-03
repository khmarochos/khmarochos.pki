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

import q

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker \
    import ChangesStack
from ansible_collections.khmarochos.pki.plugins.module_utils.exceptions \
    import PKICascadeError
from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade \
    import PKICascade
from ansible_collections.khmarochos.pki.plugins.module_utils.prepare_parameters \
    import translate_certificate_parameters


ARGUMENT_SPEC = {
    'pki_ca_cascade': {'required': True, 'type': 'dict'},
    'ca_nickname': {'required': True, 'type': 'str'},
    'certificate_parameters': {'required': True, 'type': 'dict'}
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
        module.fail_json(msg=f"Can't traverse the PKI cascade: {e.__str__()}")

    try:
        pki_cascade.setup()
    except Exception as e:
        module.fail_json(msg=f"Can't set up the PKI cascade: {e.__str__()}")

    pki_ca = None

    try:
        ca_nickname = module.params['ca_nickname']
        pki_ca = pki_cascade.get_ca(nickname=ca_nickname, loose=True)
        if pki_ca is None:
            module.fail_json(msg=f"Can't find the '{ca_nickname}' certificate authority")
    except Exception as e:
        module.fail_json(msg=f"Can't fetch the certificate authority's configuration: {e.__str__()}")

    certificate = None

    try:
        certificate_parameters = module.params['certificate_parameters']
        certificate = pki_ca.issue(**translate_certificate_parameters(certificate_parameters))
    except Exception as e:
        module.fail_json(msg=f"Can't issue a certificate: {e.__str__()}")

    module.exit_json(
        changed=bool(changes_stack.__len__() > 0),
        result=certificate.get_properties(builtins_only=True)
    )

if __name__ == '__main__':
    main()
