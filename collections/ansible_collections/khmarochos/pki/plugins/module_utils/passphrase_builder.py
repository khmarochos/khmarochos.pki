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

import os
import secrets

from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangeTracker
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexibuilder import FlexiBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


class PassphraseBuilder(ChangeTracker, FlexiBuilder, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'type': str,
        'mandatory': False,
        'readonly': False,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
        'add_builder_updater': True
    },
    'file': {},
    'value': {},
    'random': {'type': bool, 'default': Constants.DEFAULT_PASSPHRASE_RANDOM},
    'length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'character_set': {'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET}
}):

    @FlexiBuilder.parameters_assigner
    def _assign_parameters(
            self,
            parameters_to_assign: dict = None,
            parameters_to_merge: dict = None,
            parameters_assigned: dict = None
    ) -> dict:

        if parameters_assigned.get('random') is True:
            if parameters_assigned.get('length') < 1:
                raise ValueError('The length parameter cannot be less than 1 if the random parameter is True')
            elif len(parameters_assigned.get('character_set')) < 1:
                raise ValueError('The character_set parameter cannot be empty if the random parameter is True')
            elif parameters_assigned.get('value') is not None:
                raise ValueError('The value parameter cannot be set if the random parameter is True')

        return parameters_assigned

    @staticmethod
    def _check_after_load(
            passphrase: Passphrase,
            parameters_assigned: dict = None,
            raise_exception: bool = True
    ) -> bool:
        result = FlexiBuilder.check_after_load_universal(
            object_to_check=passphrase,
            parameters_assigned=parameters_assigned,
            parameters_to_check=['value', 'length'],
            raise_exception=raise_exception
        )
        return result

    def init_with_file(
            self,
            file: str = None,
    ) -> Passphrase:
        parameters_assigned = self._assign_parameters({
            'file': {'mandatory': True},
        })
        passphrase = Passphrase(**parameters_assigned)
        passphrase.load()
        PassphraseBuilder._check_after_load(passphrase, parameters_assigned)
        return passphrase

    def init_with_value(
            self,
            load_if_exists: bool = False,
            save_if_needed: bool = True,
            save_forced: bool = False,
            file: str = None,
            value: str = None
    ) -> Passphrase:
        parameters_assigned = self._assign_parameters({
            'file': {'mandatory': True},
            'value': {'mandatory': True}
        })
        file_exists = os.path.exists(parameters_assigned.get('file'))
        generated = False
        if load_if_exists and file_exists:
            passphrase = self.init_with_file(**{
                k: v for k, v in parameters_assigned.items() if k in ['file']
            })
            PassphraseBuilder._check_after_load(passphrase, parameters_assigned)
        else:
            passphrase = Passphrase(**parameters_assigned)
            generated = True
        if save_forced or (save_if_needed and generated):
            passphrase.save()
            self.changes_stack.push("Saved a passphrase")
        return passphrase

    def init_with_random(
            self,
            load_if_exists: bool = False,
            save_if_needed: bool = True,
            save_forced: bool = False,
            file: str = None,
            random: bool = None,
            length: int = None,
            character_set: str = None
    ) -> Passphrase:
        parameters_assigned = self._assign_parameters({
            'file': {'mandatory': True},
            'random': {'mandatory': True},
            'length': {},
            'character_set': {}
        })
        file_exists = os.path.exists(parameters_assigned.get('file'))
        generated = False
        if load_if_exists and file_exists:
            passphrase = self.init_with_file(**{
                k: v for k, v in parameters_assigned.items() if k in ['file']
            })
            PassphraseBuilder._check_after_load(passphrase, parameters_assigned)
        else:
            parameters_assigned['value'] = ''.join(
                secrets.choice(parameters_assigned.get('character_set'))
                    for _ in range(parameters_assigned.get('length'))
            )
            passphrase = self.init_with_value(
                load_if_exists=load_if_exists,
                save_if_needed=save_if_needed,
                save_forced=save_forced,
                **{
                    k: v for k, v in parameters_assigned.items() if k in ['file', 'value']
                }
            )
            generated = True
        if save_forced or (save_if_needed and generated):
            passphrase.save()
            self.changes_stack.push("Saved a passphrase")
        return passphrase
