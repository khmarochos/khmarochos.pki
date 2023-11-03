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

from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangeTracker
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class Passphrase(ChangeTracker, FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {'mandatory': False, 'readonly': True},
    'value': {'type': str},
    'file': {'type': str, 'mandatory': True},
    'length': {'type': int, 'fget': 'get_length'},
}):

    def load(self):
        with open(self.file, 'r') as f, self.ignore_readonly('value'):
            self.value = f.read()

    def save(self):
        with open(self.file, 'w') as f:
            f.write(self.value)

    def lookup(self) -> str:
        return self.value

    def get_length(self) -> int:
        return len(self.value) if self.value is not None else None
