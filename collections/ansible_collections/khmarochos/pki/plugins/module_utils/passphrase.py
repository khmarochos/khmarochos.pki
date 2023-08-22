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

import secrets

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class Passphrase(FlexiClass, properties={
    'llo': {'type': str},
    'file': {'type': str, 'mandatory': True},
    'random': {'type': bool, 'default': Constants.DEFAULT_PASSPHRASE_RANDOM},
    'length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'character_set': {'type': str, 'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET}
}):

    # def __init__(self, **kwargs):
    #     super().__init__(**kwargs)

    def setup(self):
        self.setup_llo()

    def setup_llo(self, force_save: bool = False, force_load: bool = False):
        generated = False
        if getattr(self, 'llo') is None or force_load:
            try:
                self.load_llo()
            except FileNotFoundError:
                if self.random:
                    self.make_llo()
                    generated = True
        if generated or force_save:
            self.save_llo()

    def load_llo(self):
        with open(self.file, 'r') as f, self.ignore_readonly('llo'):
            self.llo = f.read()

    def save_llo(self):
        with open(self.file, 'w') as f:
            f.write(self.llo)

    def make_llo(self):
        with self.ignore_readonly('llo'):
            self.llo = ''.join(secrets.choice(self.character_set) for _ in range(self.length))

    def lookup(self) -> str:
        return self.llo
