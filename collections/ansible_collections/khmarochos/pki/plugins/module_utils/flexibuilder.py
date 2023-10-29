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
import inspect
import logging
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

    @staticmethod
    def parameters_assigner(decorated_function: callable):
        def assign_parameters_universal(
                self,
                parameters_to_assign: dict = None,
                parameters_to_merge: dict = None,
                parameters_assigned: dict = None
        ) -> dict:

            if parameters_to_assign is None:
                parameters_to_assign = {}
            if parameters_to_merge is None:
                parameters_to_merge = {}
            if parameters_assigned is None:
                parameters_assigned = {}

            parameters_to_merge_extra = {}
            if (caller := inspect.currentframe().f_back) is not None:
                (args, _, _, values) = inspect.getargvalues(caller)
                for arg in args:
                    if arg != 'self':
                        parameters_to_merge_extra[arg] = values[arg]
                        # logging.debug(f'arg: {arg}, value: {values[arg]}')
            parameters_to_merge = {**parameters_to_merge, **parameters_to_merge_extra}

            # logging.debug(f'parameters_to_assign: {parameters_to_assign}')
            # logging.debug(f'parameters_to_parse: {parameters_to_merge}')

            for parameter_name, parameter_requirements in parameters_to_assign.items():
                parameter_value = getattr(self, parameter_name)
                # logging.debug(f'parameter_name: {parameter_name}, parameter_value: {parameter_value}')
                if parameter_name in parameters_to_merge and parameters_to_merge[parameter_name] is not None:
                    parameter_value = parameters_to_merge[parameter_name]
                if parameter_requirements.get('mandatory', False) and parameter_value is None:
                    raise ValueError(f"The {parameter_name} parameter is mandatory")
                if parameter_requirements.get('default', None) is not None and parameter_value is None:
                    parameter_value = parameter_requirements.get('default')
                type_to_check = parameter_requirements.get(                 # Get the type from the requirements
                    'type',                                                 # ...
                    self._object_properties.get(parameter_name, {}).get(    # Get the type from the object properties
                        'type',                                             # ...
                        object                                              # If the type is not specified anywhere,
                                                                            # we'll assume that it is an abstract object
                    )
                )
                if parameter_value is not None and not self._check_property_type(
                        property_name=parameter_name,
                        property_type=type_to_check,
                        value=parameter_value,
                        raise_exception=False
                ):
                    raise ValueError(f"The parameter {parameter_name} must be of type "
                                     f"{parameter_requirements.get('type')}")
                parameters_assigned[parameter_name] = parameter_value

            # logging.debug(f'parameters_assigned: {parameters_assigned}')

            return decorated_function(self, parameters_to_assign, parameters_to_merge, parameters_assigned)

        return assign_parameters_universal

    @staticmethod
    def check_after_load_universal(
            object_to_check: FlexiClass,
            parameters_assigned: dict,
            parameters_to_check: list[str] = None,
            raise_exception: bool = True
    ) -> bool:

        if parameters_to_check is None:
            parameters_to_check = parameters_assigned.keys()

        for parameter_name in parameters_to_check:
            if (
                    parameter_name in parameters_assigned and
                    getattr(object_to_check, parameter_name) != parameters_assigned[parameter_name]
            ):
                if raise_exception:
                    raise RuntimeError(f"The {parameter_name} parameter has been discovered, "
                                       f"its value ({getattr(object_to_check, parameter_name)}) differs from "
                                       f"the expected value ({parameters_assigned.get(parameter_name)})")
                else:
                    return False

        return True

    def reset(self, **kwargs):

        self.__init__(**kwargs)
