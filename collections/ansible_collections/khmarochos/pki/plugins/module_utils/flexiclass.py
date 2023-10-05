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
import sys
import re
from contextlib import contextmanager
from enum import Enum
from types import MethodType
from typing import Union

from ansible_collections.khmarochos.pki.plugins.module_utils.exceptions import \
    UnknownProperty, \
    MandatoryPropertyUnset, \
    ReadOnlyProperty, \
    InterpolationLoop, \
    UnbalancedBraces, \
    ReservedCharacter


# noinspection PyCompatibility
class FlexiClass:
    """@DynamicAttrs"""

    # Define the options of the interpolator's behaviour
    class InterpolatorBehaviour(Enum):
        NEVER = 0,
        ON_SET = 1,
        ON_GET = 2,

    # ...
    _class_properties = {}

    # The name of the pseudo-property that contains the default property settings
    DEFAULT_PROPERTY_SETTINGS_KEY = '__default__'

    # The default property settings
    DEFAULT_PROPERTY_SETTINGS = {
        'type': type(None),
        'mandatory': False,
        'mandatory_unless': None,
        'mandatory_unless_any': [],
        'mandatory_unless_all': [],
        'default': None,
        'readonly': True,
        'interpolate': InterpolatorBehaviour.NEVER,
        'omit': False,
        'omit_if_none': False,
        'omit_if_empty': False,
        'fget': None,
        'fset': None,
        'fdel': None,
        'fdoc': None,
    }

    # Compile the regular expression needed for the interpolator
    INTERPOLATOR_REGEX = re.compile(r'\$(?P<left_brace>{?)(?P<property>\w+)(?P<right_brace>}?)')

    # Define the reserved character for the interpolator (it's used to temporarily replace '$$')
    INTERPOLATOR_RESERVED_CHARACTER = '\0'

    #
    BUILTIN_TYPES = {
        builtin_type_name: builtin_type
        for builtin_type_name, builtin_type in (
            dict(__builtins__) if isinstance(__builtins__, dict) else {__builtins__.__dict__}
        ).items() if isinstance(builtin_type, type)
    }

    #
    # PRIVATE METHODS
    #

    def __init__(self, **kwargs):

        # q(self, kwargs)

        # Initialize the object's parameters
        self._object_properties = {}
        self._property_bindings = {}

        # Initialize the interpolator's breadcrumbs' stack
        self._interpolator_breadcrumbs = []

        # The properties that temporarily could be modified even if they are read-only. This list is used by the
        # `ignore_readonly` context: it'll add the property name to this list when we need to modify a read-only
        # property.
        self._readonly_ignored = []

        # The properties that temporarily could be updated without being marked as updated. This list is used by the
        # `hide_updates` context: it'll add the property name to this list when we need to update a property without
        # marking it as updated.
        self._hide_updates = []

        # Create all the class' properties. Although there is a strong temptation to do that in `__init_subclass__()`,
        # we really need to do this only when the object have been instantiated, as the object's reference (`self`)
        # needs to be injected into properties' getters and setters.
        for property_name in self._class_properties:
            if property_name != FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY:
                # The point is that we need to create the properties only if they are not already created. At the same
                # time, we should be ready to catch the `UnknownProperty` exception (as `hasattr() actually calls the
                # property's getter, so it will raise that exception if the property hasn't been added yet).
                try:
                    if not hasattr(self, property_name):
                        self._add_property(property_name)
                except UnknownProperty: pass

        # Parse the dictionary of the object's parameters given to the initializer.
        for property_name, property_value in kwargs.items():
            if property_name not in self._class_properties:
                raise UnknownProperty(f"The {property_name} property is unknown")
            with self.ignore_readonly(property_name):
                setattr(self, property_name, property_value)

        # Check for the mandatory parameters, assign the default values.
        for property_name, property_configuration in self._class_properties.items():
            # Skip the default property settings dictionary
            if property_name == FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY:
                continue
            if property_name not in self._object_properties and 'default' in property_configuration:
                with self.ignore_readonly(property_name), self.hide_updates(property_name):
                    setattr(self, property_name, property_configuration['default'])
            try:
                if getattr(self, property_name) is None:
                    self.ensure_none_is_legit(property_name)
            except UnknownProperty:
                pass

    def __init_subclass__(cls, properties: dict = {}, **kwargs):

        # Define the default property settings for the new class
        cls.DEFAULT_PROPERTY_SETTINGS = FlexiClass.DEFAULT_PROPERTY_SETTINGS.copy()
        if FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY in properties:
            cls.DEFAULT_PROPERTY_SETTINGS.update(properties[FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY])

        # Create the empty dictionary of the class' properties (don't use the FlexiClass._class_properties dictionary!)
        cls._class_properties = {}

        # Fill the dictionary of the class' properties with the properties' configurations
        for property_name, property_configuration in properties.items():
            # Don't touch the key of the default properties' set!
            if property_name == FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY:
                continue
            # Take the defaults from the default properties' set
            cls._class_properties[property_name] = cls.DEFAULT_PROPERTY_SETTINGS.copy()
            # Mix the property's configuration in
            cls._class_properties[property_name].update(property_configuration)

        super().__init_subclass__(**kwargs)

    def _add_property(self, property_name: str):
        fget = self._create_fget(property_name)
        fset = self._create_fset(property_name)
        # fdel = self._create_fdel(property)
        # fdoc = self._create_fdoc(property)
        property_assets = property(fget, fset)
        setattr(self.__class__, property_name, property_assets)

    def _check_property_type(self, property_name: str, property_type, value, raise_exception: bool = True) -> bool:

        # As the `property_type` could be a string, we need to convert it to a class
        possible_types = self._possible_types(property_type) + (type(None),)

        # Now we're ready to check the type
        if not isinstance(value, possible_types):
            if raise_exception:
                raise TypeError(
                    f"The {property_name} property must be of type {possible_types}, not {type(value)}")
            else:
                return False
        else:
            return True

    def _possible_types(self, probably_a_type) -> Union[type, tuple[type]]:
        detected_type = None
        if isinstance(probably_a_type, type):
            detected_type = probably_a_type,
        elif isinstance(probably_a_type, str):
            if '.' in probably_a_type:
                module_name, class_name = probably_a_type.rsplit('.', 1)
                module = sys.modules.get(module_name)
                if module:
                    detected_type = (getattr(module, class_name),)
                else:
                    raise TypeError(f"The {probably_a_type} class is unknown")
            else:
                detected_type = self.BUILTIN_TYPES.get(probably_a_type)
        elif hasattr(probably_a_type, '__origin__') and probably_a_type.__origin__ is Union:
            detected_type = tuple(probably_a_type.__args__)
        else:
            raise TypeError(f"Expected to get a type or a Union of type or a string representing a type's name, "
                            f"got a {type(probably_a_type)}")

        if detected_type is None:
            raise TypeError(f"The {probably_a_type} doesn't seem to be a valid type at all")

        return detected_type

    def _create_fget(self, property_name: str):

        property_settings = self.__class__._class_properties[property_name]

        def _fget(myself):

            value = None

            # Call the sub-getter if it's defined or get the value from the object's parameters
            if property_name in myself._property_bindings:
                backend_object = myself._property_bindings[property_name]['object']
                backend_property = myself._property_bindings[property_name]['property']
                value = getattr(backend_object, backend_property)
            elif callable(property_settings['fget']):
                value = property_settings['fget']()
            elif isinstance(property_settings['fget'], str):
                value = getattr(myself, property_settings['fget'])()
            elif property_name not in myself._class_properties:
                raise UnknownProperty(f"The {property_name} property is unknown")
            elif (object_propetries := myself._object_properties.get(property_name)) is not None:
                value = object_propetries.get('value')
            else:
                value = None

            # Interpolating variables
            if property_settings['interpolate'] == FlexiClass.InterpolatorBehaviour.ON_GET:
                value = myself._interpolator(value)

            # Type checking
            self._check_property_type(
                property_name=property_name,
                property_type=property_settings['type'],
                value=value
            )

            return value

        return _fget

    def _create_fset(self, property_name: str):

        property_settings = self.__class__._class_properties[property_name]

        def _fset(myself, value, record_update: bool = True):

            # Value checking
            if value is None:
                self.ensure_none_is_legit(property_name)
            elif property_settings['readonly'] and property_name not in myself._readonly_ignored:
                raise ReadOnlyProperty(f"The {property_name} property of {myself.__class__.__name__} is readonly")

            # Type checking
            self._check_property_type(
                property_name=property_name,
                property_type=property_settings['type'],
                value=value
            )
            # Interpolating variables
            if property_settings['interpolate'] == FlexiClass.InterpolatorBehaviour.ON_SET:
                value = myself._interpolator(value)

            # Call the sub-setter if it's defined or set the value to the object's parameters
            if property_name in myself._property_bindings:
                backend_object = myself._property_bindings[property_name]['object']
                backend_property = myself._property_bindings[property_name]['property']
                with backend_object.ignore_readonly(backend_property):
                    setattr(backend_object, backend_property, value)
            elif callable(property_settings['fset']):
                property_settings['fset'](value)
            elif isinstance(property_settings['fset'], str):
                getattr(myself, property_settings['fset'])(value)
            else:
                if property_name not in myself._object_properties:
                    myself._object_properties[property_name] = {}
                myself._object_properties[property_name]['value'] = value

            if property_name not in myself._hide_updates:
                myself._object_properties[property_name]['updated'] = True

        return _fset

    def _interpolator(self, string: str):

        def call_getter(match: re.Match):
            if bool(match.group('left_brace')) != bool(match.group('right_brace')):
                raise UnbalancedBraces(f"Unbalanced curly braces in {match.string}")
            if match.group('property') not in self._class_properties:
                raise UnknownProperty(f"Unknown property {match.group('property')} in {match.string}")
            if match.group('property') in self._interpolator_breadcrumbs:
                raise InterpolationLoop(f"Interpolation loop detected in {match.string} ({match.group('property')})")
            self._interpolator_breadcrumbs.append(match.group('property'))
            result = getattr(self, match.group('property'))
            self._interpolator_breadcrumbs.pop()
            return result

        if not isinstance(string, str):
            return string
        if FlexiClass.INTERPOLATOR_RESERVED_CHARACTER in string:
            raise ReservedCharacter(f"The '{FlexiClass.INTERPOLATOR_RESERVED_CHARACTER}' character can't be used")

        string = string.replace('$$', FlexiClass.INTERPOLATOR_RESERVED_CHARACTER)
        string = FlexiClass.INTERPOLATOR_REGEX.sub(call_getter, string)
        string = string.replace(FlexiClass.INTERPOLATOR_RESERVED_CHARACTER, '$$')
        return string

    def _bind_properties(self, target_objects: list):
        for target_object in target_objects:
            object = target_object['object']
            for property_backend, property_frontend in target_object['properties'].items():
                if property_frontend not in self._class_properties:
                    raise UnknownProperty(f"The {property_frontend} property is unknown for {self.__class__.__name__}")
                if property_backend not in object._class_properties:
                    raise UnknownProperty(f"The {property_backend} property is unknown for {object.__class__.__name__}")
                self._property_bindings[property_frontend] = {
                    'object': object,
                    'property': property_backend
                }

    def _bind_arguments(self, property_bindings):
        return {
            property_backend: getattr(self, property_frontend)
            for property_backend, property_frontend in property_bindings.items()
        }

    def _from_kwargs_or_properties(self, property_name: str):
        result = None
        if (caller := inspect.currentframe().f_back) is not None:
            (args, _, _, values) = inspect.getargvalues(caller)
            result = values.get(property_name)
        if result is None:
            result = getattr(self, property_name)
        return result

    #
    # PUBLIC METHODS
    #

    # This method is called in a temporary context when we need to set a read-only property's value.
    @contextmanager
    def ignore_readonly(self, property_name: str):
        if property_name not in self._class_properties:
            raise UnknownProperty(f"The {property_name} property is unknown")
        self._readonly_ignored.append(property_name)
        try:
            yield
        finally:
            self._readonly_ignored.remove(property_name)

    @contextmanager
    def hide_updates(self, property_name: str):
        if property_name not in self._class_properties:
            raise UnknownProperty(f"The {property_name} property is unknown")
        self._hide_updates.append(property_name)
        try:
            yield
        finally:
            self._hide_updates.remove(property_name)

    # def get_property(self, field_name: str):
    #     field_value = getattr(self, field_name)
    #     if isinstance(field_value, FlexiClass):
    #         return field_value.get_properties()
    #     else:
    #         return field_value

    def property_updated(self, property_name: str) -> bool:
        return self._object_properties.get(property_name, {}).get('updated', False)

    def get_properties(self, builtins_only: bool = False):
        properties = {}
        for property_name, property_parameters in self._class_properties.items():
            property_value = getattr(self, property_name)
            if property_parameters['omit']:
                pass
            elif property_parameters['omit_if_none'] and property_value is None:
                pass
            elif property_parameters['omit_if_empty'] and property_value == '':
                pass
            # elif isinstance(property_value, FlexiClass):
            #     properties[property_name] = property_value.get_properties(builtins_only=builtins_only)
            elif True \
                    and builtins_only \
                    and property_parameters['type'] not in self.BUILTIN_TYPES.values() \
                    and property_parameters['type'] not in self.BUILTIN_TYPES.keys():
                pass
            else:
                properties[property_name] = property_value
        return properties

    def ensure_none_is_legit(self, property_name: str, raise_exception: bool = True):
        property_configuration = self._class_properties[property_name]
        to_check = []
        if property_configuration['mandatory']:
            to_check.append({'name': property_name, 'sufficient': False})
        if property_configuration['mandatory_unless']:
            to_check.append({'name': property_configuration['mandatory_unless'], 'sufficient': False})
        for property_to_check in property_configuration['mandatory_unless_all']:
            to_check.append({'name': property_to_check, 'sufficient': False})
        # Remember that all checks of "sufficient" properties MUST be performed only at the end, so that's
        # crucial to append them to the end of the list!
        for property_to_check in property_configuration['mandatory_unless_any']:
            to_check.append({'name': property_to_check, 'sufficient': True})
        failed = False
        for property_to_check in to_check:
            if not property_to_check['sufficient']:
                if getattr(self, property_to_check['name']) is None:
                    failed = True
                    break
            # The "sufficient" properties are being checked only after all the "non-sufficient" checks
            # are passed, so we suppose that the check is failed by default.
            else:
                failed = True
                if getattr(self, property_to_check['name']) is not None:
                    failed = False
                    break
        if failed and raise_exception:
            raise MandatoryPropertyUnset(f"The {property_name} is not set ({to_check})")
        else:
            return not failed
