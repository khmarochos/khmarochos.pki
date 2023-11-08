from ansible.module_utils.basic import AnsibleModule
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleLookupError
from ansible.template import Templar
from ansible.utils.display import Display

from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade import PKICascade


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
        return[result]
