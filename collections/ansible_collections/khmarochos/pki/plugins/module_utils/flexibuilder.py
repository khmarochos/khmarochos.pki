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
from types import MethodType

from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class FlexiBuilder(FlexiClass):

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        for property_name, property_parameters in self._class_properties.items():
            if property_name != FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY and \
                    (add_builder_updater := property_parameters.get('add_builder_updater')):
                self.__add_builder_updater(property_name, add_builder_updater)

    def __add_builder_updater(self, property_name: str, method_name: bool or str or None):

        def __builder_updater(myself, value):
            setattr(myself, property_name, value)
            return myself

        if type(method_name) is bool:
            method_name = 'add_' + property_name if method_name is True else None
        if method_name is not None:
            setattr(self, method_name, MethodType(__builder_updater, self))

    def reset(self, **kwargs):

        self.__init__(**kwargs)
