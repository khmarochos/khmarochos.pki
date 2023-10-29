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
import random
import sys
import unittest
import tempfile
import logging
from enum import Enum
from typing import Optional, Union, Any

from parameterized import parameterized

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase_builder import PassphraseBuilder
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderTestType as TT, \
    Randomizer, StopAfter, TestingSet
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderCheckList
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import AbstractBuilderTest


class TestPassphraseBuilder(unittest.TestCase, AbstractBuilderTest):

    class TPParametersPassing(Enum):
        CONSTRUCTOR = 'passing parameters to the constructor'
        RUNTIME = 'adding parameters at runtime'
        FINAL_CALL = 'passing parameters with the final call'

    class TPValuesAssignment(Enum):
        DEFAULT = 'using default values'
        DEFINED = 'using defined values'

    class TPInit(Enum):
        NEW = 'creating a new passphrase'
        FROM_FILE = 'get a private key from a file'

    PARAMETER_SETS = []
    for tp_parameters_passing in list(TPParametersPassing):
        for tp_values_assignment in list(TPValuesAssignment):
            PARAMETER_SETS.append((
                '__'.join((
                    tp_parameters_passing.name,
                    tp_values_assignment.name,
                )),
                tp_parameters_passing,
                tp_values_assignment
            ))

    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler(sys.stdout)])

    @parameterized.expand(PARAMETER_SETS)
    def test_everything(self, name, tp_parameters_passing, tp_values_assignment):

        randomizer = Randomizer()

        testset_parameters = {
            'provided': {
                'testset': {},
                'builder': {},
            },
            'expected': {
                'builder': {},
                'outcome': {},
            }
        }
        provided_to_testset = testset_parameters['provided']['testset']
        provided_to_builder = testset_parameters['provided']['builder']
        expected_in_builder = testset_parameters['expected']['builder']
        expected_in_outcome = testset_parameters['expected']['outcome']

        provided_to_testset['nickname'] = randomizer
        if tp_values_assignment == TestPassphraseBuilder.TPValuesAssignment.DEFINED:
            provided_to_testset['passphrase_length'] = randomizer
            provided_to_testset['passphrase_character_set'] = randomizer
        elif tp_values_assignment == TestPassphraseBuilder.TPValuesAssignment.DEFAULT:
            pass
        else:
            raise ValueError(f'Unexpected tp_values value: {tp_values_assignment}')

        testset = TestingSet(stop_after=StopAfter.PASSPHRASE, **provided_to_testset)

        provided_to_builder['file'] = testset.passphrase_file_name
        expected_in_builder['file'] = testset.passphrase_file_name
        expected_in_outcome['file'] = testset.passphrase_file_name
        if tp_values_assignment == TestPassphraseBuilder.TPValuesAssignment.DEFINED:
            expected_in_builder['value'] = testset.passphrase_value
            provided_to_builder['random'] = testset.passphrase_random
            expected_in_builder['random'] = testset.passphrase_random
            expected_in_outcome['random'] = testset.passphrase_random
            provided_to_builder['length'] = testset.passphrase_length
            expected_in_builder['length'] = testset.passphrase_length
            expected_in_outcome['length'] = testset.passphrase_length
            provided_to_builder['character_set'] = testset.passphrase_character_set
            expected_in_builder['character_set'] = testset.passphrase_character_set
        elif tp_values_assignment == TestPassphraseBuilder.TPValuesAssignment.DEFAULT:
            expected_in_builder['random'] = Constants.DEFAULT_PASSPHRASE_RANDOM
            expected_in_outcome['random'] = Constants.DEFAULT_PASSPHRASE_RANDOM
            expected_in_builder['length'] = Constants.DEFAULT_PASSPHRASE_LENGTH
            expected_in_outcome['length'] = Constants.DEFAULT_PASSPHRASE_LENGTH
            expected_in_builder['character_set'] = Constants.DEFAULT_PASSPHRASE_CHARACTER_SET
        else:
            raise ValueError(f'Unexpected tp_values_assignment value: {tp_values_assignment}')

        logging.debug(
            '%s: %s; %s.',
            name,
            tp_parameters_passing.value,
            tp_values_assignment.value
        )
        logging.debug(f'Parameters provided to the testset: {provided_to_testset}')
        logging.debug(f'Parameters provided to the builder: {provided_to_builder}')
        logging.debug(f'Parameters expected in the builder: {expected_in_builder}')
        logging.debug(f'Parameters expected in the outcome: {expected_in_outcome}')

        passphrase = None

        for tp_init in list(TestPassphraseBuilder.TPInit):

            if tp_parameters_passing == TestPassphraseBuilder.TPParametersPassing.CONSTRUCTOR:
                passphrase_builder = PassphraseBuilder(**provided_to_builder)
            elif tp_parameters_passing == TestPassphraseBuilder.TPParametersPassing.RUNTIME:
                passphrase_builder = PassphraseBuilder()
                for parameter_name, parameter_value in provided_to_builder.items():
                    setattr(passphrase_builder, parameter_name, parameter_value)
            elif tp_parameters_passing == TestPassphraseBuilder.TPParametersPassing.FINAL_CALL:
                passphrase_builder = PassphraseBuilder()
            else:
                raise ValueError(f'Unexpected tp_parameters_passing value: {tp_parameters_passing}')

            if tp_parameters_passing != TestPassphraseBuilder.TPParametersPassing.FINAL_CALL:
                self._test_builder(
                    _builder=passphrase_builder,
                    file=expected_in_builder['file'],
                    value=expected_in_builder.get('value', (TT.NONE,)),
                    random=expected_in_builder['random'],
                    length=expected_in_builder['length'],
                    character_set=expected_in_builder['character_set']
                )
            else:
                self._test_builder(
                    _builder=passphrase_builder,
                    file=(TT.NONE,),
                    value=(TT.NONE,),
                    random=Constants.DEFAULT_PASSPHRASE_RANDOM,
                    length=Constants.DEFAULT_PASSPHRASE_LENGTH,
                    character_set=Constants.DEFAULT_PASSPHRASE_CHARACTER_SET,
                )

            if tp_init == TestPassphraseBuilder.TPInit.NEW:
                passphrase = passphrase_builder.init_with_random(**(
                    provided_to_builder
                    if tp_parameters_passing == TestPassphraseBuilder.TPParametersPassing.FINAL_CALL
                    else {}
                ))
                expected_in_outcome['value'] = passphrase.value
            elif tp_init == TestPassphraseBuilder.TPInit.FROM_FILE:
                passphrase = passphrase_builder.init_with_file(file=expected_in_builder['file'])
            else:
                raise ValueError(f'Unexpected tp_init value: {tp_init}')

            self._test_passphrase(
                _passphrase=passphrase,
                file=expected_in_outcome['file'],
                value=expected_in_outcome['value'],
                length=expected_in_outcome['length'],
            )

    # def setUp(self) -> None:
    #     self.encoding = 'utf-8'
    #
    #     self.foo = self.random_string()
    #     for i in range(0, 10):
    #         self.length = random.randrange(
    #             AbstractBuilderTest.MIN_RANDOM_STRING_LENGTH,
    #             AbstractBuilderTest.MAX_RANDOM_STRING_LENGTH
    #         )
    #         if self.length != Constants.DEFAULT_PASSPHRASE_LENGTH:
    #             break
    #     if i == 9:
    #         raise RuntimeError(f"Could not find a random length different from {Constants.DEFAULT_PASSPHRASE_LENGTH}")
    #     self.character_set = '0123456789'
    #     if len(self.character_set) >= len(Constants.DEFAULT_PASSPHRASE_CHARACTER_SET) / 8:
    #         raise RuntimeError(f"The custom character set ({self.character_set}) "
    #                            "must be at least 8 times narrower from "
    #                            f"the default one ({Constants.DEFAULT_PASSPHRASE_CHARACTER_SET})")
    #     self.temporary_file = tempfile.NamedTemporaryFile()
    #     self.temporary_file_name = self.temporary_file.name

    def _test_builder(
            self,
            _builder: PassphraseBuilder,
            file: BuilderCheckList[str],
            value: BuilderCheckList[str],
            random: BuilderCheckList[bool],
            length: BuilderCheckList[int],
            character_set: BuilderCheckList[str]
    ):
        self._test_object(
            _object_to_test=_builder,
            file=file,
            value=value,
            random=random,
            length=length,
            character_set=character_set
        )

    def _test_passphrase(
            self,
            _passphrase: Passphrase,
            file: BuilderCheckList[str],
            value: BuilderCheckList[str],
            length: BuilderCheckList[int],
    ):
        self._test_object(
            _object_to_test=_passphrase,
            file=file,
            value=value,
            length=length,
        )

    #
    # Test parametrization
    #

    # # Test parameters passed to the constructor
    #
    # def test_parameters_passed_to_constructor(self):
    #     builder = PassphraseBuilder(
    #         file=self.temporary_file_name,
    #         random=True,
    #         length=self.length,
    #         character_set=self.character_set
    #     )
    #     self._test_builder(
    #         builder,
    #         file=self.temporary_file_name,
    #         value=(TT.NONE,),
    #         random=(TT.TRUE,),
    #         length=self.length,
    #         character_set=self.character_set
    #     )
    #     passphrase = builder.init_with_random()
    #     self._test_passphrase(
    #         passphrase,
    #         file=self.temporary_file_name,
    #         value=[
    #             (TT.NOT_EMPTY,),
    #             (TT.ISINSTANCE, str),
    #             (TT.LAMBDA, lambda x: all(character in self.character_set for character in x))
    #         ],
    #         length=self.length,
    #     )
    #
    # def test_parameters_passed_to_constructor_with_default_values(self):
    #     builder = PassphraseBuilder(
    #         file=self.temporary_file_name,
    #         random=True
    #     )
    #     self._test_builder(
    #         builder,
    #         file=self.temporary_file_name,
    #         value=(TT.NONE,),
    #         random=(TT.TRUE,),
    #         length=Constants.DEFAULT_PASSPHRASE_LENGTH,
    #         character_set=Constants.DEFAULT_PASSPHRASE_CHARACTER_SET
    #     )
    #     passphrase = builder.init_with_random()
    #     self._test_passphrase(
    #         passphrase,
    #         file=self.temporary_file_name,
    #         value=[
    #             (TT.NOT_EMPTY,),
    #             (TT.ISINSTANCE, str),
    #             (TT.LAMBDA, lambda x: all(character in Constants.DEFAULT_PASSPHRASE_CHARACTER_SET for character in x))
    #         ],
    #         length=Constants.DEFAULT_PASSPHRASE_LENGTH
    #     )
    #
    # # Test parameters added at runtime
    #
    # def test_parameters_added_at_runtime(self):
    #     builder = PassphraseBuilder() \
    #         .add_file(self.temporary_file_name) \
    #         .add_random(True) \
    #         .add_length(self.length) \
    #         .add_character_set(self.character_set)
    #     self._test_builder(
    #         builder,
    #         file=self.temporary_file_name,
    #         value=(TT.NONE,),
    #         random=(TT.TRUE,),
    #         length=self.length,
    #         character_set=self.character_set
    #     )
    #     passphrase = builder.init_with_random()
    #     self._test_passphrase(
    #         passphrase,
    #         file=self.temporary_file_name,
    #         value=[
    #             (TT.NOT_EMPTY,),
    #             (TT.ISINSTANCE, str),
    #             (TT.LAMBDA, lambda x: all(character in self.character_set for character in x))
    #         ],
    #         length=self.length,
    #     )
    #
    # def test_parameters_added_at_runtime_with_default_values(self):
    #     builder = PassphraseBuilder() \
    #         .add_file(self.temporary_file_name) \
    #         .add_random(True)
    #     self._test_builder(
    #         builder,
    #         file=self.temporary_file_name,
    #         value=(TT.NONE,),
    #         random=(TT.TRUE,),
    #         length=Constants.DEFAULT_PASSPHRASE_LENGTH,
    #         character_set=Constants.DEFAULT_PASSPHRASE_CHARACTER_SET
    #     )
    #     passphrase = builder.init_with_random()
    #     self._test_passphrase(
    #         passphrase,
    #         file=self.temporary_file_name,
    #         value=[
    #             (TT.NOT_EMPTY,),
    #             (TT.ISINSTANCE, str),
    #             (TT.LAMBDA, lambda x: all(character in Constants.DEFAULT_PASSPHRASE_CHARACTER_SET for character in x))
    #         ],
    #         length=Constants.DEFAULT_PASSPHRASE_LENGTH
    #     )
    #
    # # Test parameters passed to the final call
    #
    # def test_parameters_passed_with_final_call(self):
    #     passphrase = PassphraseBuilder() \
    #         .init_with_random(
    #             file=self.temporary_file_name,
    #             random=True,
    #             length=self.length,
    #             character_set=self.character_set
    #         )
    #     self._test_passphrase(
    #         passphrase,
    #         file=self.temporary_file_name,
    #         value=[
    #             (TT.NOT_EMPTY,),
    #             (TT.ISINSTANCE, str),
    #             (TT.LAMBDA, lambda x: all(character in self.character_set for character in x))
    #         ],
    #         length=self.length,
    #     )
    #
    # def test_parameters_passed_with_final_call_with_default_values(self):
    #     passphrase = PassphraseBuilder() \
    #         .init_with_random(
    #             file=self.temporary_file_name,
    #             random=True
    #     )
    #     self._test_passphrase(
    #         passphrase,
    #         file=self.temporary_file_name,
    #         value=[
    #             (TT.NOT_EMPTY,),
    #             (TT.ISINSTANCE, str),
    #             (TT.LAMBDA, lambda x: all(character in Constants.DEFAULT_PASSPHRASE_CHARACTER_SET for character in x))
    #         ],
    #         length=Constants.DEFAULT_PASSPHRASE_LENGTH
    #     )
    #
    # #
    # # Test init_with_file()
    # #
    #
    # def test_with_file_non_existent(self):
    #     temporary_directory = tempfile.TemporaryDirectory()
    #     non_existent_file_name = f"{temporary_directory.name}/non-existent-file"
    #     if os.path.exists(non_existent_file_name):
    #         raise RuntimeError(f"The file {non_existent_file_name} exists")
    #     temporary_directory.cleanup()
    #     with self.assertRaises(FileNotFoundError):
    #         PassphraseBuilder() \
    #             .add_file(non_existent_file_name) \
    #             .init_with_file()
    #
    # def test_with_file_existent(self):
    #     passphrase_saved = PassphraseBuilder() \
    #         .add_file(self.temporary_file_name) \
    #         .add_random(True) \
    #         .add_length(self.length) \
    #         .add_character_set(self.character_set) \
    #         .init_with_random()
    #     passphrase = PassphraseBuilder() \
    #         .add_file(self.temporary_file_name) \
    #         .init_with_file()
    #     self._test_passphrase(
    #         passphrase,
    #         file=self.temporary_file_name,
    #         value=passphrase_saved.lookup(),
    #         length=passphrase_saved.length,
    #     )
    #
    # #
    # # Test init_with_value()
    # #
    #
    # def test_with_value(self):
    #     passphrase = PassphraseBuilder() \
    #         .add_file(self.temporary_file_name) \
    #         .add_value(self.foo) \
    #         .init_with_value()
    #     self._test_passphrase(
    #         passphrase,
    #         file=self.temporary_file_name,
    #         value=self.foo,
    #         length=len(self.foo),
    #     )
    #
    # #
    # # Test init_with_random()
    # #
    #
    # def test_with_random(self):
    #     passphrase = PassphraseBuilder() \
    #         .add_file(self.temporary_file_name) \
    #         .add_random(True) \
    #         .init_with_random()
    #     self._test_passphrase(
    #         passphrase,
    #         file=self.temporary_file_name,
    #         value=[
    #             (TT.NOT_EMPTY,),
    #             (TT.ISINSTANCE, str),
    #             (TT.LAMBDA, lambda x: all(character in Constants.DEFAULT_PASSPHRASE_CHARACTER_SET for character in x))
    #         ],
    #         length=Constants.DEFAULT_PASSPHRASE_LENGTH
    #     )
    #
    #
    # def test_with_random_random_false(self):
    #     with self.assertRaises(ValueError):
    #         PassphraseBuilder() \
    #             .add_file(self.temporary_file_name) \
    #             .add_random(False) \
    #             .init_with_random()
    #
    # def test_with_random_length_0(self):
    #     with self.assertRaises(ValueError):
    #         PassphraseBuilder() \
    #             .add_file(self.temporary_file_name) \
    #             .add_random(True) \
    #             .add_length(0) \
    #             .init_with_random()
    #
    # def test_with_random_length(self):
    #     length = random.randrange(AbstractBuilderTest.MIN_RANDOM_STRING_LENGTH, AbstractBuilderTest.MAX_RANDOM_STRING_LENGTH)
    #     passphrase = PassphraseBuilder() \
    #         .add_file(self.temporary_file_name) \
    #         .add_random(True) \
    #         .add_length(length) \
    #         .init_with_random()
    #     self._test_passphrase(
    #         passphrase,
    #         file=self.temporary_file_name,
    #         value=[
    #             (TT.NOT_EMPTY,),
    #             (TT.ISINSTANCE, str),
    #             (TT.LAMBDA, lambda x: all(character in Constants.DEFAULT_PASSPHRASE_CHARACTER_SET for character in x))
    #         ],
    #         length=length
    #     )
    #
    # #
    # # Test reset()
    # #
    #
    # def test_reset(self):
    #     builder = PassphraseBuilder()
    #     self.assertIsNone(builder.file)
    #     self.assertIsNone(builder.value)
    #     self.assertFalse(builder.random)
    #     self.assertEqual(Constants.DEFAULT_PASSPHRASE_LENGTH, builder.length)
    #     self.assertEqual(Constants.DEFAULT_PASSPHRASE_CHARACTER_SET, builder.character_set)
    #     builder = builder \
    #         .add_file(self.temporary_file_name) \
    #         .add_value(self.foo) \
    #         .add_random(True) \
    #         .add_length(self.length) \
    #         .add_character_set(self.character_set)
    #     self._test_builder(
    #         builder,
    #         file=self.temporary_file_name,
    #         value=self.foo,
    #         random=True,
    #         length=self.length,
    #         character_set=self.character_set
    #     )
    #     builder.reset()
    #     self._test_builder(
    #         builder,
    #         file=(TT.NONE,),
    #         value=(TT.NONE,),
    #         random=False,
    #         length=Constants.DEFAULT_PASSPHRASE_LENGTH,
    #         character_set=Constants.DEFAULT_PASSPHRASE_CHARACTER_SET
    #     )