from ansible.module_utils.basic import AnsibleModule
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleLookupError
from ansible.template import Templar
from ansible.utils.display import Display

from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade import PKICascade

DOCUMENTATION = r'''
---
name: pki_dictionary
author: khmarochos
version_added: "0.0.1"
short_description: Lookup PKI dictionary or CA properties
description:
  - Retrieves PKI cascade dictionary or specific CA properties from the PKI configuration
  - Can return the entire PKI cascade dictionary or properties for a specific CA
options:
  _terms:
    description: Terms for the lookup (not used in this implementation)
    required: false
  ca:
    description: The nickname of the certificate authority to query
    required: false
    type: str
  parameter:
    description: Specific parameter/property to retrieve from the CA
    required: false
    type: str
requirements:
  - pki_cascade_configuration variable must be set
notes:
  - Requires pki_cascade_configuration to be defined in variables
  - If no ca is specified, returns the entire PKI cascade dictionary
  - If ca is specified but no parameter, returns all CA properties
  - If both ca and parameter are specified, returns the specific property value
'''

EXAMPLES = r'''
# Get the entire PKI cascade dictionary
- debug:
    var: lookup('khmarochos.pki.pki_dictionary')

# Get all properties for a specific CA
- debug:
    var: lookup('khmarochos.pki.pki_dictionary', ca='root-ca')

# Get a specific property from a CA
- debug:
    var: lookup('khmarochos.pki.pki_dictionary', ca='root-ca', parameter='certificate_path')
'''

RETURN = r'''
_raw:
  description: 
    - PKI cascade dictionary when no ca specified
    - CA properties dictionary when ca specified but no parameter
    - Specific property value when both ca and parameter specified
  type: list
  elements: raw
'''


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        display = Display()
        templar = Templar(loader=self._loader, variables=variables)
        if (pki_cascade_configuration := variables.get('pki_cascade_configuration')) is None:
            raise AnsibleLookupError("The PKI cascade isn't configured")
        pki_cascade_configuration = templar.template(pki_cascade_configuration)
        if (pki_cascade := PKICascade(
            pki_cascade_configuration=pki_cascade_configuration,
            changes_stack=None
        )) is None:
            raise AnsibleLookupError("The PKI cascade isn't set up")
        if kwargs.get('ca', None) is None:
            return [pki_cascade.pki_cascade_dictionary()]
        if (pkica := pki_cascade.get_ca(nickname=kwargs['ca'], loose=True)) is None:
            raise AnsibleLookupError(f"Can't find the '{kwargs['ca']}' certificate authority")
        if kwargs.get('parameter', None) is None:
            return [pkica.get_properties(builtins_only=True)]
        result = getattr(pkica, kwargs['parameter'])
        return [result]
