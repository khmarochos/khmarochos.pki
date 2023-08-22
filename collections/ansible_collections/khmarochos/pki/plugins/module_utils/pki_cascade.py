import jsons
import json

import q

from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.pki_ca import PKICA
from ansible_collections.khmarochos.pki.plugins.module_utils.key import Key
from ansible_collections.khmarochos.pki.plugins.module_utils.exceptions import CANotFound, StructureError


class PKICascade(FlexiClass, properties={
    'pki_cascade_configuration': {
        'mandatory': True,
        'default': None,
        'readonly': False,
        'type': dict
    },
    'pki_cascade': {
        'default': dict(),
        'type': dict
    }
}):
    PARAMETERS_KEY = '__parameters'
    PROPAGATED_KEY = '__propagated'
    SPECIAL_KEYS = [PARAMETERS_KEY, PROPAGATED_KEY]

    def __init__(self, pki_cascade_configuration: dict = None, **kwargs):
        super().__init__(pki_cascade_configuration=pki_cascade_configuration, **kwargs)
        # self.pki_cascade = {}
        self.traverse_cascade(
            branch=pki_cascade_configuration,
            nickname=None,
            parent_nickname=None
        )

    def traverse_cascade(
            self,
            branch: dict,
            nickname: str = None,
            parent_nickname: str = None,
            parameters: dict = None
    ):
        # Initialise the propagated parameters' dictionary
        parameters_propagated = dict() if parameters is None else parameters.copy()
        # Update the propagated parameters' dictionary
        if PKICascade.PROPAGATED_KEY in branch:
            parameters_propagated.update(branch[PKICascade.PROPAGATED_KEY])
        # Initialise the parameters' dictionary
        parameters = parameters_propagated.copy()
        # Update the parameters' dictionary
        if PKICascade.PARAMETERS_KEY in branch:
            if nickname is None:
                raise StructureError("The root node cannot contain parameters")
            parameters.update(branch[PKICascade.PARAMETERS_KEY])
        # If this branch contains parameters of some CA, add the CA to the cascade
        if nickname is not None:
            pki_ca = PKICA(pki_cascade=self, nickname=nickname, parent_nickname=parent_nickname, **parameters)
            self.add_ca(pki_ca)
        # If there are branches, traverse them
        for child_nickname, child_branch in branch.items():
            if child_nickname not in PKICascade.SPECIAL_KEYS:
                self.traverse_cascade(
                    branch=child_branch,
                    nickname=child_nickname,
                    parent_nickname=nickname,
                    parameters=parameters_propagated
                )

    def add_ca(self, pki_ca: PKICA) -> None:
        self.pki_cascade.update({pki_ca.nickname: pki_ca})

    def get_ca(self, nickname: str, loose: bool = False) -> PKICA:
        ca = self.pki_cascade[nickname] if nickname in self.pki_cascade else None
        if ca is not None or loose:
            return ca
        else:
            raise CANotFound(f"There is no such CA as {nickname}")

    def pki_cascade_json(self):
        result = {nickname: pki_ca.get_properties() for nickname, pki_ca in self.pki_cascade.items()}
        return jsons.dumps(result, indent=4, sort_keys=True)
