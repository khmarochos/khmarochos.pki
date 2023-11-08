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

import datetime
import inspect
from typing import Union

from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class Change(FlexiClass, properties={
    'time': {'mandatory': False, 'default': None, 'readonly': True, 'type': datetime.datetime},
    'traceback': {'mandatory': False, 'default': None, 'readonly': True, 'type': list},
    'comment': {'mandatory': False, 'default': None, 'readonly': True, 'type': str}
}):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get('time') is None:
            with self.ignore_readonly('time'):
                self.time = datetime.datetime.now()
        if kwargs.get('traceback') is None:
            with self.ignore_readonly('traceback'):
                self.traceback = inspect.stack()[1:]


class ChangesStack:

    def __init__(self):
        self._changes_stack: list[Change] = []

    def __len__(self) -> int:
        return len(self._changes_stack)

    def state(self, change: Union[Change, str]) -> Change:
        if type(change) is str:
            change = Change(comment=change)
        self._changes_stack.append(change)
        return change

    def list(self) -> list[Change]:
        return self._changes_stack


class ChangeTracker:

    def __init__(self, changes_stack: ChangesStack = None, **kwargs):
        super().__init__(changes_stack=changes_stack, **kwargs)
        if self.changes_stack is None:
            with self.ignore_readonly('changes_stack'):
                self.changes_stack = ChangesStack()

    def __init_subclass__(cls, **kwargs):
        if kwargs.get('properties') is None:
            kwargs['properties'] = {}
        kwargs.get('properties').update({
            'changes_stack': {'mandatory': False, 'default': None, 'readonly': True, 'type': ChangesStack}
        })
        super().__init_subclass__(**kwargs)
