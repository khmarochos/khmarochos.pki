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
import random
import secrets
import unittest
from enum import Enum
from abc import ABC, abstractmethod
from typing import TypeVar, Any, Tuple, Union, List, Generic

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants


class BuilderTestType(Enum):
    SKIP = 'skip'
    EQUAL = 'equal'
    NOT_EQUAL = 'not_equal'
    NONE = 'none'
    NOT_NONE = 'not_none'
    ZERO = 'zero'
    NON_ZERO = 'non_zero'
    EMPTY = 'empty'
    NOT_EMPTY = 'not_empty'
    TRUE = 'true'
    FALSE = 'false'
    ISINSTANCE = 'isinstance'
    NOT_ISINSTANCE = 'not_isinstance'
    IN = 'in'
    NOT_IN = 'not_in'
    LAMBDA = 'lambda'


__T = TypeVar("__T")
BuilderCheckListElement = Union[Tuple[BuilderTestType], Tuple[BuilderTestType, Any], __T]
BuilderCheckList = Union[BuilderCheckListElement[__T], List[BuilderCheckListElement[__T]]]


class AbstractBuilderTest(ABC):
    MIN_RANDOM_STRING_LENGTH = 16
    MAX_RANDOM_STRING_LENGTH = 32

    @staticmethod
    def random_string(
            length: int = random.randrange(MIN_RANDOM_STRING_LENGTH, MAX_RANDOM_STRING_LENGTH),
            character_set: str = Constants.DEFAULT_PASSPHRASE_CHARACTER_SET
    ) -> str:
        return ''.join(secrets.choice(character_set) for _ in range(length))

    def _test_object(self: unittest.TestCase, _object_to_test, **kwargs) -> bool:

        def _test_value(check_type: BuilderTestType, actual_value, expected_value, failure_message_prefix: str) -> bool:

            if check_type == BuilderTestType.SKIP:
                pass
            elif check_type == BuilderTestType.EQUAL:
                self.assertEqual(
                    expected_value,
                    actual_value,
                    f"{failure_message_prefix}: expected {expected_value}, got {actual_value}"
                )

            elif check_type == BuilderTestType.NOT_EQUAL:
                self.assertNotEqual(
                    expected_value,
                    actual_value,
                    f"{failure_message_prefix}: expected anything but {expected_value}, got {actual_value}"
                )

            elif check_type == BuilderTestType.NONE:
                self.assertIsNone(
                    actual_value,
                    f"{failure_message_prefix}: expected None, got {actual_value}"
                )

            elif check_type == BuilderTestType.NOT_NONE:
                self.assertIsNotNone(
                    actual_value,
                    f"{failure_message_prefix}: expected anything but None, got {actual_value}"
                )

            elif check_type == BuilderTestType.ZERO:
                self.assertEqual(
                    0,
                    actual_value,
                    f"{failure_message_prefix}: expected 0, got {actual_value}"
                )

            elif check_type == BuilderTestType.NON_ZERO:
                self.assertNotEqual(
                    0,
                    actual_value,
                    f"{failure_message_prefix}: expected anything but 0, got {actual_value}"
                )

            elif check_type == BuilderTestType.EMPTY:
                self.assertEqual(
                    '',
                    actual_value,
                    f"{failure_message_prefix}: expected empty string, got {actual_value}"
                )

            elif check_type == BuilderTestType.NOT_EMPTY:
                self.assertNotEqual(
                    '',
                    actual_value,
                    f"{failure_message_prefix}: expected anything but empty string, got {actual_value}"
                )

            elif check_type == BuilderTestType.TRUE:
                self.assertTrue(
                    actual_value,
                    f"{failure_message_prefix}: expected True, got {actual_value}"
                )

            elif check_type == BuilderTestType.FALSE:
                self.assertFalse(
                    actual_value,
                    f"{failure_message_prefix}: expected False, got {actual_value}"
                )

            elif check_type == BuilderTestType.ISINSTANCE:
                if not isinstance(expected_value, type):
                    raise ValueError(f'Expected value {expected_value} is not a type')
                self.assertIsInstance(
                    actual_value,
                    expected_value,
                    f"{failure_message_prefix}: "
                    f"expected an instance of {expected_value}, got {actual_value}"
                    f" of type {type(actual_value)}"
                )

            elif check_type == BuilderTestType.NOT_ISINSTANCE:
                if not isinstance(expected_value, type):
                    raise ValueError(f'Expected value {expected_value} is not a type')
                self.assertNotIsInstance(
                    actual_value,
                    expected_value,
                    f"{failure_message_prefix}: "
                    f"expected anything but an instance of {expected_value}, got {actual_value}"
                    f" of type {type(actual_value)}"
                )

            elif check_type == BuilderTestType.IN:
                if not isinstance(expected_value, list):
                    raise ValueError(f'Expected value {expected_value} is not a list')
                self.assertIn(
                    expected_value,
                    actual_value,
                    f"{failure_message_prefix}: expected {actual_value} to be in {expected_value}"
                )

            elif check_type == BuilderTestType.NOT_IN:
                if not isinstance(expected_value, list):
                    raise ValueError(f'Expected value {expected_value} is not a list')
                self.assertNotIn(
                    expected_value,
                    actual_value,
                    f"{failure_message_prefix}: expected {actual_value} to be not in {expected_value}"
                )

            elif check_type == BuilderTestType.LAMBDA:
                if not isinstance(expected_value, type(lambda: None)):
                    raise ValueError(f'Expected value {expected_value} is not a lambda')
                self.assertTrue(
                    expected_value(actual_value),
                    f"{failure_message_prefix}: expected {actual_value} to pass lambda {expected_value}"
                )

            else:
                raise ValueError(f'Unknown check type {check_type}')

            return True

        def _test_values(
                check_type: BuilderTestType,
                expected_values,
                actual_value,
                failure_message_prefix: str = None
        ):
            for expected_value in expected_values if isinstance(expected_values, list) else [expected_values]:
                if (result := _test_value(
                        check_type,
                        actual_value,
                        expected_value,
                        failure_message_prefix
                )) is False:
                    return result
            return True

        for property_name, property_checks in kwargs.items():
            if property_checks is None:
                continue
            for property_check in property_checks if isinstance(property_checks, list) else [property_checks]:
                property_check_type = BuilderTestType.EQUAL
                expected_values = [property_check]
                if isinstance(property_check, tuple):
                    property_check_type = property_check[0]
                    if len(property_check) > 2:
                        expected_values = property_check[1:]
                    elif len(property_check) > 1:
                        expected_values = property_check[1]
                actual_value = getattr(_object_to_test, property_name)
                if (result := _test_values(
                        property_check_type,
                        expected_values,
                        actual_value,
                        f"Property {property_name} of {_object_to_test} failed expectations:"
                )) is False:
                    return result
        return True

    @abstractmethod
    def setUpClass(self):
        pass

    @abstractmethod
    def setUp(self):
        pass

    @abstractmethod
    def tearDown(self):
        pass

    @abstractmethod
    def _test_builder(self, **kwargs):
        pass

    @abstractmethod
    def test_parameters_passed_to_constructor(self):
        pass

    @abstractmethod
    def test_parameters_passed_to_constructor_with_default_values(self):
        pass

    @abstractmethod
    def test_parameters_added_at_runtime(self):
        pass

    @abstractmethod
    def test_parameters_added_at_runtime_with_default_values(self):
        pass

    @abstractmethod
    def test_parameters_passed_with_final_call(self):
        pass

    @abstractmethod
    def test_parameters_passed_with_final_call_with_default_values(self):
        pass

    @abstractmethod
    def test_reset(self, **kwargs):
        pass
