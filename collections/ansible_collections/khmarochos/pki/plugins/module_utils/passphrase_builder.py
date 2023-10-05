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

import logging
import secrets

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexibuilder import FlexiBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


class PassphraseBuilder(FlexiBuilder, properties={
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

    def init_with_file(
            self,
            file: str = None
    ) -> Passphrase:
        if self.property_updated('value') and self.value is not None:
            logging.warning('The value parameter is ignored when using init_with_random()')
        if self.property_updated('random') and self.random is True:
            logging.warning('The random parameter is ignored when using init_with_value()')
        if self.property_updated('length') and self.length is not None:
            logging.warning('The length parameter is ignored when using init_with_value()')
        if self.property_updated('character_set') and self.character_set is not None:
            logging.warning('The character_set parameter is ignored when using init_with_value()')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        passphrase = Passphrase(file=file)
        passphrase.load()
        return passphrase

    def init_with_value(
            self,
            file: str = None,
            value: str = None,
            save: bool = True
    ) -> Passphrase:
        if self.property_updated('random') and self.random is True:
            logging.warning('The random parameter is ignored when using init_with_value()')
        if self.property_updated('length') and self.length is not None:
            logging.warning('The length parameter is ignored when using init_with_value()')
        if self.property_updated('character_set') and self.character_set is not None:
            logging.warning('The character_set parameter is ignored when using init_with_value()')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if (value := self._from_kwargs_or_properties('value')) is None:
            raise ValueError('The value parameter cannot be None')
        passphrase = Passphrase(value=value, file=file)
        if save:
            passphrase.save()
        return passphrase

    def init_with_random(
            self,
            file: str = None,
            random: bool = None,
            length: int = None,
            character_set: str = None,
            save: bool = True
    ) -> Passphrase:
        if self.property_updated('value') and self.value is not None:
            logging.warning('The value parameter is ignored when using init_with_random()')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if (random := self._from_kwargs_or_properties('random')) is False:
            raise ValueError('The random parameter cannot be False')
        if (length := self._from_kwargs_or_properties('length')) < 1:
            raise ValueError('The length parameter cannot be less than 1')
        if len(character_set := self._from_kwargs_or_properties('character_set')) < 1:
            raise ValueError('The character_set parameter cannot be empty')
        value = ''.join(secrets.choice(character_set) for _ in range(length))
        passphrase = Passphrase(value=value, file=file)
        if save:
            passphrase.save()
        return passphrase
