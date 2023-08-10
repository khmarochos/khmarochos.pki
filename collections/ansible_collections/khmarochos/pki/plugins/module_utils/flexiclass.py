from contextlib import contextmanager
import re
from enum import Enum

import q
import jsons
from types import NoneType

from ansible_collections.khmarochos.pki.plugins.module_utils.exceptions import \
    UnknownProperty, \
    MandatoryPropertyUnset, \
    ReadOnlyProperty, \
    InterpolationLoop, \
    UnbalancedBraces, \
    ReservedCharacter


# noinspection PyCompatibility
class FlexiClass:

    # Define the options of the interpolator's behaviour
    class InterpolatorBehaviour(Enum):
        NEVER = 0,
        ON_SET = 1,
        ON_GET = 2,

    # The name of the pseudo-property that contains the default property settings
    DEFAULT_PROPERTY_SETTINGS_KEY = '__default__'

    # The default property settings
    DEFAULT_PROPERTY_SETTINGS = {
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': InterpolatorBehaviour.NEVER,
        'type': NoneType,
        'omit_if_none': False,
        'omit_if_empty': False,
        'omit': False,
        'fget': None,
        'fset': None
    }

    # ...
    _class_properties = {}

    # Compile the regular expression needed for the interpolator
    INTERPOLATOR_REGEX = re.compile(r'\$(?P<left_brace>{?)(?P<property>\w+)(?P<right_brace>}?)')

    # Define the reserved character for the interpolator (it's used to temporarily replace '$$')
    INTERPOLATOR_RESERVED_CHARACTER = '\0'

    #
    # PRIVATE METHODS
    #

    def __init__(self, **kwargs):

        # Initialize the object's parameters
        self._object_parameters = {}

        # Initialize the interpolator's breadcrumbs' stack
        self._interpolator_breadcrumbs = []

        # The properties that temporarily could be modified even if they are read-only. This list is used by the
        # `_ignore_readonly` context: it'll add the property name to this list when we need to modify a read-only
        # property.
        self._readonly_ignored = []

        # Create all the class' properties. Although there is a strong temptation to do that in `__init_subclass__()`,
        # we really need to do this only when the object have been instantiated, as the object's reference (`self`)
        # needs to be injected into properties' getters and setters.
        for property_name in self._class_properties:
            if property_name != FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY:
                # The point is that we need to create the properties only if they are not already created. At the same
                # time, we should be ready to catch the `MandatoryPropertyUnset` exception, as it's possible that the
                # property is mandatory and it's not set yet (keep in mind that `hasattr()` calls the property's
                # getter!).
                try:
                    if not hasattr(self, property_name):
                        self._create_properties(property_name)
                except MandatoryPropertyUnset:
                    pass

        # Parse the dictionary of the object's parameters given to the initializer.
        for property_name, property_value in kwargs.items():
            if property_name not in self._class_properties:
                raise UnknownProperty(f"The {property_name} property is unknown")
            with self._ignore_readonly(property_name):
                setattr(self, property_name, property_value)

        # Check for the mandatory parameters, assign the default values.
        for property_name, property_configuration in self._class_properties.items():
            if property_name != FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY and getattr(self, property_name) is None:
                # Check for mandatory parameters
                if 'mandatory' in property_configuration and property_configuration['mandatory']:
                    raise MandatoryPropertyUnset(f"The {property_name} property is mandatory but is unset")
                # Assign default values
                if property_name not in self._object_parameters and 'default' in property_configuration:
                    with self._ignore_readonly(property_name):
                        setattr(self, property_name, property_configuration['default'])

    def __init_subclass__(cls, properties: dict, **kwargs):

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

    # This method is called in a temporary context when we need to set a read-only property's value.
    @contextmanager
    def _ignore_readonly(self, property_name: str):
        if property_name not in self._class_properties:
            raise UnknownProperty(f"The {property_name} property is unknown")
        self._readonly_ignored.append(property_name)
        try:
            yield
        finally:
            self._readonly_ignored.remove(property_name)

    def _create_properties(self, property_name: str):
        fget = self._create_fget(property_name)
        fset = self._create_fset(property_name)
        # fdel = self._create_fdel(property)
        # fdoc = self._create_fdoc(property)
        property_assets = property(fget, fset)
        setattr(self.__class__, property_name, property_assets)

    def _create_fget(self, property: str):

        property_settings = self._class_properties[property]

        def fget_default(self):
            if property not in self._object_parameters:
                return None
            elif property_settings['interpolate'] == FlexiClass.InterpolatorBehaviour.ON_GET:
                return self._interpolator(self._object_parameters[property])
            else:
                return self._object_parameters[property]

        if callable(property_settings['fget']):
            fget = property_settings['fget']
        else:
            fget = fget_default

        return fget

    def _create_fset(self, property: str):

        property_settings = self._class_properties[property]

        def fset_default(self, value):
            if property_settings['mandatory'] and value is None:
                raise MandatoryPropertyUnset(f"The {property} property is mandatory but is unset")
            elif not isinstance(value, (property_settings['type'], NoneType)):
                raise TypeError(f"The {property} property must be of type {self._class_properties[property]['type']}, "
                                f"not {type(value)}")
            elif property_settings['interpolate'] == FlexiClass.InterpolatorBehaviour.ON_SET:
                self._object_parameters[property] = self._interpolator(value)
            else:
                self._object_parameters[property] = value

        def fset_default_readonly(self, value):
            if property in self._readonly_ignored:
                fset_default(self, value)
            else:
                raise ReadOnlyProperty(f"The {property} property is readonly")

        if callable(property_settings['fset']):
            fset = property_settings['fset']
        elif property_settings['readonly']:
            fset = fset_default_readonly
        else:
            fset = fset_default

        return fset

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

    #
    # PUBLIC METHODS
    #
    def get_property(self, field_name: str):
        field_value = getattr(self, field_name)
        if isinstance(field_value, FlexiClass):
            return field_value.get_properties()
        else:
            return field_value

    def get_properties(self):
        properties = {}
        for property_name, property_parameters in self._class_properties.items():
            property_value = self.get_property(property_name)
            if property_parameters['omit']:
                continue
            elif property_parameters['omit_if_none'] and property_value is None:
                continue
            elif property_parameters['omit_if_empty'] and property_value == '':
                continue
            else:
                properties[property_name] = property_value
        return properties
