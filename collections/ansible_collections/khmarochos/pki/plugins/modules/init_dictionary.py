#!/usr/bin/python


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
