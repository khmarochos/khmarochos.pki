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

from __future__ import annotations

import os
import sys
import unittest
import tempfile
import logging
from enum import Enum
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from parameterized import parameterized

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key_builder import PrivateKeyBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase_builder import PassphraseBuilder
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderTestType as TT, \
    Randomizer, StopAfter, TestingSet
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderCheckList
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import AbstractBuilderTest


# noinspection DuplicatedCode
class TestPrivateKeyBuilder(unittest.TestCase, AbstractBuilderTest):

    class TPParametersPassing(Enum):
        CONSTRUCTOR = 'passing parameters to the constructor'
        RUNTIME = 'adding parameters at runtime'
        FINAL_CALL = 'passing parameters with the final call'

    class TPValuesAssignment(Enum):
        DEFAULT = 'using default values'
        DEFINED = 'using defined values'

    class TPEncryptionAlgorithm(Enum):
        NO_ENCRYPTION = 'no encryption'
        BEST_AVAILABLE_ENCRYPTION = 'best available encryption'

    class TPInit(Enum):
        NEW = 'creating a new private key'
        LOAD_LLO = 'load a private key from rsa.RSAPrivateKey'
        LOAD_FILE = 'load a private key from a file'

    PARAMETER_SETS = []
    for tp_parameters_passing in list(TPParametersPassing):
        for tp_values_assignment in list(TPValuesAssignment):
            for tp_encryption_algorithm in list(TPEncryptionAlgorithm):
                PARAMETER_SETS.append((
                    '__'.join((
                        tp_parameters_passing.name,
                        tp_values_assignment.name,
                        tp_encryption_algorithm.name,
                    )),
                    tp_parameters_passing,
                    tp_values_assignment,
                    tp_encryption_algorithm,
                ))

    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler(sys.stdout)])

    def _test_builder(
            self,
            _builder: PrivateKeyBuilder,
            nickname: BuilderCheckList[str],
            llo: BuilderCheckList[rsa.RSAPrivateKey],
            file: BuilderCheckList[str],
            size: BuilderCheckList[int],
            public_exponent: BuilderCheckList[int],
            encrypted: BuilderCheckList[bool],
            encryption_algorithm: BuilderCheckList[serialization.KeySerializationEncryption],
            passphrase: BuilderCheckList[Callable],
    ):
        self._test_object(
            _object_to_test=_builder,
            nickname=nickname,
            llo=llo,
            file=file,
            size=size,
            public_exponent=public_exponent,
            encrypted=encrypted,
            encryption_algorithm=encryption_algorithm,
            passphrase=passphrase
        )

    def _test_private_key(
            self,
            _private_key: PrivateKey,
            nickname: BuilderCheckList[str],
            llo: BuilderCheckList[rsa.RSAPrivateKey],
            file: BuilderCheckList[str],
            size: BuilderCheckList[int],
            public_modulus: BuilderCheckList[int],
            public_exponent: BuilderCheckList[int],
            public_key: BuilderCheckList[rsa.RSAPublicKey],
            encrypted: BuilderCheckList[bool],
            encryption_algorithm: BuilderCheckList[serialization.KeySerializationEncryption],
            passphrase: BuilderCheckList[Callable],
    ):
        self._test_object(
            _object_to_test=_private_key,
            nickname=nickname,
            llo=llo,
            file=file,
            size=size,
            public_modulus=public_modulus,
            public_exponent=public_exponent,
            public_key=public_key,
            encrypted=encrypted,
            encryption_algorithm=encryption_algorithm,
            passphrase=passphrase
        )

    @parameterized.expand(PARAMETER_SETS)
    def test_everything(self, name, tp_parameters_passing, tp_values_assignment, tp_encryption_algorithm):

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
        provided_to_testset['passphrase_random'] = True
        if tp_values_assignment == TestPrivateKeyBuilder.TPValuesAssignment.DEFINED:
            provided_to_testset['passphrase_length'] = randomizer
            provided_to_testset['passphrase_character_set'] = randomizer
            provided_to_testset['private_key_size'] = randomizer
            provided_to_testset['private_key_public_exponent'] = randomizer
            provided_to_testset['private_key_encrypted'] = False
            provided_to_testset['private_key_encryption_algorithm'] = serialization.NoEncryption()
        elif tp_values_assignment == TestPrivateKeyBuilder.TPValuesAssignment.DEFAULT:
            pass
        else:
            raise ValueError(f'Unexpected tp_values value: {tp_values_assignment}')

        testset = TestingSet(stop_after=StopAfter.PRIVATE_KEY, **provided_to_testset)

        provided_to_builder['nickname'] = testset.nickname
        expected_in_builder['nickname'] = testset.nickname
        expected_in_outcome['nickname'] = testset.nickname
        provided_to_builder['file'] = testset.private_key_file_name
        expected_in_builder['file'] = testset.private_key_file_name
        expected_in_outcome['file'] = testset.private_key_file_name
        if tp_values_assignment == TestPrivateKeyBuilder.TPValuesAssignment.DEFINED:
            provided_to_builder['size'] = testset.private_key_size
            expected_in_builder['size'] = testset.private_key_size
            expected_in_outcome['size'] = testset.private_key_size
            provided_to_builder['public_exponent'] = testset.private_key_public_exponent
            expected_in_builder['public_exponent'] = testset.private_key_public_exponent
            expected_in_outcome['public_exponent'] = testset.private_key_public_exponent
            provided_to_builder['encrypted'] = testset.private_key_encrypted
            expected_in_builder['encrypted'] = testset.private_key_encrypted
            expected_in_outcome['encrypted'] = testset.private_key_encrypted
            provided_to_builder['encryption_algorithm'] = testset.private_key_encryption_algorithm
            expected_in_builder['encryption_algorithm'] = testset.private_key_encryption_algorithm
            expected_in_outcome['encryption_algorithm'] = testset.private_key_encryption_algorithm
        elif tp_values_assignment == TestPrivateKeyBuilder.TPValuesAssignment.DEFAULT:
            expected_in_builder['size'] = Constants.DEFAULT_PRIVATE_KEY_SIZE
            expected_in_outcome['size'] = Constants.DEFAULT_PRIVATE_KEY_SIZE
            expected_in_builder['public_exponent'] = Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT
            expected_in_outcome['public_exponent'] = Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT
            expected_in_builder['encrypted'] = Constants.DEFAULT_PRIVATE_KEY_ENCRYPTED
            expected_in_outcome['encrypted'] = Constants.DEFAULT_PRIVATE_KEY_ENCRYPTED
            expected_in_builder['encryption_algorithm'] = serialization.NoEncryption()
            expected_in_outcome['encryption_algorithm'] = serialization.NoEncryption()
        else:
            raise ValueError(f'Unexpected tp_values value: {tp_values_assignment}')
        if tp_encryption_algorithm == TestPrivateKeyBuilder.TPEncryptionAlgorithm.BEST_AVAILABLE_ENCRYPTION:
            provided_to_builder['passphrase'] = testset.passphrase
            expected_in_builder['passphrase'] = testset.passphrase
            expected_in_outcome['passphrase'] = testset.passphrase
        elif tp_encryption_algorithm == TestPrivateKeyBuilder.TPEncryptionAlgorithm.NO_ENCRYPTION:
            expected_in_builder['passphrase'] = None
            expected_in_builder['encryption_algorithm'] = serialization.NoEncryption()
            expected_in_outcome['passphrase'] = None
            expected_in_outcome['encryption_algorithm'] = serialization.NoEncryption()
        else:
            raise ValueError(f'Unexpected tp_encryption_algorithm value: {tp_encryption_algorithm}')

        logging.debug(
            '%s: %s; %s; %s.',
            name,
            tp_parameters_passing.value,
            tp_encryption_algorithm.value,
            tp_values_assignment.value
        )
        logging.debug('Parameters provided to the testset: %s', provided_to_testset)
        logging.debug('Parameters provided to the builder: %s', provided_to_builder)
        logging.debug('Parameters expected from the builder: %s', expected_in_builder)
        logging.debug('Parameters expected from the outcome: %s', expected_in_outcome)

        private_key = None

        for tp_init in list(TestPrivateKeyBuilder.TPInit):

            if tp_parameters_passing == TestPrivateKeyBuilder.TPParametersPassing.CONSTRUCTOR:
                private_key_builder = PrivateKeyBuilder(**provided_to_builder)
            elif tp_parameters_passing == TestPrivateKeyBuilder.TPParametersPassing.RUNTIME:
                private_key_builder = PrivateKeyBuilder()
                for parameter_name, parameter_value in provided_to_builder.items():
                    setattr(private_key_builder, parameter_name, parameter_value)
            elif tp_parameters_passing == TestPrivateKeyBuilder.TPParametersPassing.FINAL_CALL:
                private_key_builder = PrivateKeyBuilder()
            else:
                raise ValueError(f'Unknown test parameter value ({tp_parameters_passing})')

            if tp_parameters_passing != TestPrivateKeyBuilder.TPParametersPassing.FINAL_CALL:
                self._test_builder(
                    _builder=private_key_builder,
                    nickname=expected_in_builder['nickname'],
                    llo=(TT.NONE,),
                    file=expected_in_builder['file'],
                    size=expected_in_builder['size'],
                    public_exponent=expected_in_builder['public_exponent'],
                    encrypted=expected_in_builder['encrypted'],
                    encryption_algorithm=(TT.ISINSTANCE, type(expected_in_builder['encryption_algorithm'])),
                    passphrase=expected_in_builder['passphrase'],
                )
            else:
                self._test_builder(
                    _builder=private_key_builder,
                    nickname=(TT.NONE,),
                    llo=(TT.NONE,),
                    file=(TT.NONE,),
                    size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
                    public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
                    encrypted=Constants.DEFAULT_PRIVATE_KEY_ENCRYPTED,
                    encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
                    passphrase=(TT.NONE,),
                )

            if tp_init == TestPrivateKeyBuilder.TPInit.NEW:
                private_key = private_key_builder.init_new(**(
                    provided_to_builder
                    if tp_parameters_passing == TestPrivateKeyBuilder.TPParametersPassing.FINAL_CALL
                    else {}
                ))
                expected_in_outcome['public_modulus'] = private_key.public_modulus
                expected_in_outcome['private_numbers'] = private_key.llo.private_numbers()
                expected_in_outcome['public_numbers'] = private_key.llo.public_key().public_numbers()
            elif tp_init == TestPrivateKeyBuilder.TPInit.LOAD_LLO:
                private_key = PrivateKeyBuilder().init_with_llo(
                    nickname=private_key.nickname,
                    file=private_key.file,
                    llo=private_key.llo,
                    passphrase=private_key.passphrase
                )
            elif tp_init == TestPrivateKeyBuilder.TPInit.LOAD_FILE:
                private_key = PrivateKeyBuilder().init_with_file(
                    nickname=private_key.nickname,
                    file=private_key.file,
                    passphrase=private_key.passphrase
                )
            else:
                raise ValueError(f'Unknown test parameter value ({tp_init})')

            self._test_private_key(
                _private_key=private_key,
                nickname=expected_in_outcome['nickname'],
                llo=(TT.LAMBDA, [
                    lambda x: x.public_key().public_numbers().n == expected_in_outcome['public_numbers'].n,
                    lambda x: x.public_key().public_numbers().e == expected_in_outcome['public_numbers'].e,
                    lambda x: x.private_numbers().p == expected_in_outcome['private_numbers'].p,
                    lambda x: x.private_numbers().q == expected_in_outcome['private_numbers'].q,
                    lambda x: x.private_numbers().d == expected_in_outcome['private_numbers'].d,
                    lambda x: x.private_numbers().dmp1 == expected_in_outcome['private_numbers'].dmp1,
                    lambda x: x.private_numbers().dmq1 == expected_in_outcome['private_numbers'].dmq1,
                    lambda x: x.private_numbers().iqmp == expected_in_outcome['private_numbers'].iqmp,
                ]),
                file=expected_in_outcome['file'],
                size=expected_in_outcome['size'],
                public_modulus=expected_in_outcome['public_modulus'],
                public_exponent=expected_in_outcome['public_exponent'],
                public_key=(TT.LAMBDA, [
                    lambda x: x.public_numbers().n == expected_in_outcome['public_numbers'].n,
                    lambda x: x.public_numbers().e == expected_in_outcome['public_numbers'].e,
                ]),
                encrypted=expected_in_outcome['encrypted'],
                encryption_algorithm=(TT.ISINSTANCE, type(expected_in_outcome['encryption_algorithm'])),
                passphrase=expected_in_outcome['passphrase']
            )

            logging.debug('Private key: %s', private_key)

    # #
    # # Test parametrization
    # #
    #
    # # Test parameters passed to the constructor
    #
    # def test_parameters_passed_to_constructor(self):
    #     builder = PrivateKeyBuilder(
    #         nickname=self.nickname,
    #         llo=None,
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_exponent=self.public_exponent,
    #         encrypted=True,
    #         encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase.lookup().encode()),
    #         passphrase=self.passphrase
    #     )
    #     self._test_builder(
    #         builder,
    #         nickname=self.nickname,
    #         llo=(TT.NONE,),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_exponent=self.public_exponent,
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #     private_key = builder.init_new()
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_modulus=(TT.LAMBDA, lambda x: x > 0),
    #         public_exponent=self.public_exponent,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #
    # def test_parameters_passed_to_constructor_with_default_values(self):
    #     builder = PrivateKeyBuilder(
    #         nickname=self.nickname,
    #         file=self.temporary_private_key_file_name,
    #     )
    #     self._test_builder(
    #         builder,
    #         nickname=self.nickname,
    #         llo=(TT.NONE,),
    #         file=self.temporary_private_key_file_name,
    #         size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
    #         public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
    #         encrypted=(TT.FALSE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
    #         passphrase=(TT.NONE,)
    #     )
    #     private_key = builder.init_new()
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
    #         file=self.temporary_private_key_file_name,
    #         size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
    #         public_modulus=(TT.LAMBDA, lambda x: x > 0),
    #         public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.FALSE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
    #         passphrase=(TT.NONE,)
    #     )
    #
    # # Test parameters added at runtime
    #
    # def test_parameters_added_at_runtime(self):
    #     builder = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_size(self.size) \
    #         .add_public_exponent(self.public_exponent) \
    #         .add_encrypted(True) \
    #         .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
    #         .add_passphrase(self.passphrase)
    #     self._test_builder(
    #         builder,
    #         nickname=self.nickname,
    #         llo=(TT.NONE,),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_exponent=self.public_exponent,
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #     private_key = builder.init_new()
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_modulus=(TT.LAMBDA, lambda x: x > 0),
    #         public_exponent=self.public_exponent,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #
    # def test_parameters_added_at_runtime_with_default_values(self):
    #     builder = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name)
    #     self._test_builder(
    #         builder,
    #         nickname=self.nickname,
    #         llo=(TT.NONE,),
    #         file=self.temporary_private_key_file_name,
    #         size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
    #         public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
    #         encrypted=(TT.FALSE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
    #         passphrase=(TT.NONE,)
    #     )
    #     private_key = builder.init_new()
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
    #         file=self.temporary_private_key_file_name,
    #         size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
    #         public_modulus=(TT.LAMBDA, lambda x: x > 0),
    #         public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.FALSE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
    #         passphrase=(TT.NONE,)
    #     )
    #
    # # Test parameters passed with the final call
    #
    # def test_parameters_passed_with_final_call(self):
    #     private_key = PrivateKeyBuilder() \
    #         .init_new(
    #         nickname=self.nickname,
    #         file=self.temporary_private_key_file_name,
    #         encrypted=True,
    #         passphrase=self.passphrase,
    #         size=self.size,
    #         public_exponent=self.public_exponent,
    #         encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase.lookup().encode())
    #     )
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_modulus=(TT.LAMBDA, lambda x: x > 0),
    #         public_exponent=self.public_exponent,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #
    # def test_parameters_passed_with_final_call_with_default_values(self):
    #     private_key = PrivateKeyBuilder() \
    #         .init_new(
    #         nickname=self.nickname,
    #         file=self.temporary_private_key_file_name
    #     )
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
    #         file=self.temporary_private_key_file_name,
    #         size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
    #         public_modulus=(TT.LAMBDA, lambda x: x > 0),
    #         public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.FALSE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
    #         passphrase=(TT.NONE,)
    #     )
    #
    # #
    # # Test init_with_file()
    # #
    #
    # def test_with_file_non_existent(self):
    #     temporary_directory = tempfile.TemporaryDirectory()
    #     non_existent_file_name = f"{temporary_directory.name}/{self.nickname}"
    #     if os.path.exists(non_existent_file_name):
    #         raise RuntimeError(f"The file {non_existent_file_name} exists")
    #     temporary_directory.cleanup()
    #     with self.assertRaises(FileNotFoundError):
    #         PrivateKeyBuilder() \
    #             .add_nickname(self.nickname) \
    #             .add_file(non_existent_file_name) \
    #             .init_with_file()
    #
    # def test_with_file_existent_and_encrypted(self):
    #     private_key = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_size(self.size) \
    #         .add_public_exponent(self.public_exponent) \
    #         .add_encrypted(True) \
    #         .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
    #         .add_passphrase(self.passphrase) \
    #         .init_new()
    #     private_key_saved_llo = private_key.llo
    #     private_key = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_encrypted(True) \
    #         .add_passphrase(self.passphrase) \
    #         .init_with_file()
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_modulus=private_key_saved_llo.public_key().public_numbers().n,
    #         public_exponent=self.public_exponent,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #
    # def test_with_file_existent_and_not_encrypted(self):
    #     private_key = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_size(self.size) \
    #         .add_public_exponent(self.public_exponent) \
    #         .add_encrypted(False) \
    #         .init_new()
    #     private_key_saved_llo = private_key.llo
    #     private_key = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .init_with_file()
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_modulus=private_key_saved_llo.public_key().public_numbers().n,
    #         public_exponent=self.public_exponent,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.FALSE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
    #         passphrase=(TT.NONE,)
    #     )
    #
    # #
    # # Test init_new()
    # #
    #
    # def test_loading_if_exists_and_encrypted(self):
    #     private_key = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_size(self.size) \
    #         .add_public_exponent(self.public_exponent) \
    #         .add_encrypted(True) \
    #         .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
    #         .add_passphrase(self.passphrase) \
    #         .init_new()
    #     private_key_saved_llo = private_key.llo
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == private_key_saved_llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == private_key_saved_llo.public_key().public_numbers().e,
    #             lambda x: x.private_numbers().p == private_key_saved_llo.private_numbers().p,
    #             lambda x: x.private_numbers().q == private_key_saved_llo.private_numbers().q,
    #             lambda x: x.private_numbers().d == private_key_saved_llo.private_numbers().d,
    #             lambda x: x.private_numbers().dmp1 == private_key_saved_llo.private_numbers().dmp1,
    #             lambda x: x.private_numbers().dmq1 == private_key_saved_llo.private_numbers().dmq1,
    #             lambda x: x.private_numbers().iqmp == private_key_saved_llo.private_numbers().iqmp,
    #         ]),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_modulus=private_key_saved_llo.public_key().public_numbers().n,
    #         public_exponent=self.public_exponent,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #     private_key = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_size(self.size) \
    #         .add_public_exponent(self.public_exponent) \
    #         .add_encrypted(True) \
    #         .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
    #         .add_passphrase(self.passphrase) \
    #         .init_new(load_if_exists=True)
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == private_key_saved_llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == private_key_saved_llo.public_key().public_numbers().e,
    #             lambda x: x.private_numbers().p == private_key_saved_llo.private_numbers().p,
    #             lambda x: x.private_numbers().q == private_key_saved_llo.private_numbers().q,
    #             lambda x: x.private_numbers().d == private_key_saved_llo.private_numbers().d,
    #             lambda x: x.private_numbers().dmp1 == private_key_saved_llo.private_numbers().dmp1,
    #             lambda x: x.private_numbers().dmq1 == private_key_saved_llo.private_numbers().dmq1,
    #             lambda x: x.private_numbers().iqmp == private_key_saved_llo.private_numbers().iqmp,
    #         ]),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_modulus=private_key_saved_llo.public_key().public_numbers().n,
    #         public_exponent=self.public_exponent,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #
    # def test_loading_if_exists_and_not_encrypted(self):
    #     private_key = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_size(self.size) \
    #         .add_public_exponent(self.public_exponent) \
    #         .add_encrypted(False) \
    #         .init_new()
    #     private_key_saved_llo = private_key.llo
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == private_key_saved_llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == private_key_saved_llo.public_key().public_numbers().e,
    #             lambda x: x.private_numbers().p == private_key_saved_llo.private_numbers().p,
    #             lambda x: x.private_numbers().q == private_key_saved_llo.private_numbers().q,
    #             lambda x: x.private_numbers().d == private_key_saved_llo.private_numbers().d,
    #             lambda x: x.private_numbers().dmp1 == private_key_saved_llo.private_numbers().dmp1,
    #             lambda x: x.private_numbers().dmq1 == private_key_saved_llo.private_numbers().dmq1,
    #             lambda x: x.private_numbers().iqmp == private_key_saved_llo.private_numbers().iqmp,
    #         ]),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_modulus=private_key_saved_llo.public_key().public_numbers().n,
    #         public_exponent=self.public_exponent,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.FALSE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
    #         passphrase=(TT.NONE,)
    #     )
    #     private_key = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_size(self.size) \
    #         .add_public_exponent(self.public_exponent) \
    #         .add_encrypted(False) \
    #         .add_encryption_algorithm(serialization.NoEncryption()) \
    #         .init_new(load_if_exists=True)
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == private_key_saved_llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == private_key_saved_llo.public_key().public_numbers().e,
    #             lambda x: x.private_numbers().p == private_key_saved_llo.private_numbers().p,
    #             lambda x: x.private_numbers().q == private_key_saved_llo.private_numbers().q,
    #             lambda x: x.private_numbers().d == private_key_saved_llo.private_numbers().d,
    #             lambda x: x.private_numbers().dmp1 == private_key_saved_llo.private_numbers().dmp1,
    #             lambda x: x.private_numbers().dmq1 == private_key_saved_llo.private_numbers().dmq1,
    #             lambda x: x.private_numbers().iqmp == private_key_saved_llo.private_numbers().iqmp,
    #         ]),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_modulus=private_key_saved_llo.public_key().public_numbers().n,
    #         public_exponent=self.public_exponent,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.FALSE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
    #         passphrase=(TT.NONE,)
    #     )
    #
    # def test_not_loading_if_exists_with_mismatches(self):
    #     private_key = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_size(self.size) \
    #         .add_public_exponent(self.public_exponent) \
    #         .add_encrypted(True) \
    #         .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
    #         .add_passphrase(self.passphrase) \
    #         .init_new()
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_modulus=(TT.LAMBDA, lambda x: x > 0),
    #         public_exponent=self.public_exponent,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #     with self.assertRaises(RuntimeError):
    #         PrivateKeyBuilder() \
    #             .add_nickname(self.nickname) \
    #             .add_file(self.temporary_private_key_file_name) \
    #             .add_size(Constants.DEFAULT_PRIVATE_KEY_SIZE) \
    #             .add_public_exponent(self.public_exponent) \
    #             .add_encrypted(True) \
    #             .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
    #             .add_passphrase(self.passphrase) \
    #             .init_new(load_if_exists=True)
    #     with self.assertRaises(RuntimeError):
    #         PrivateKeyBuilder() \
    #             .add_nickname(self.nickname) \
    #             .add_file(self.temporary_private_key_file_name) \
    #             .add_size(self.size) \
    #             .add_public_exponent(Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT) \
    #             .add_encrypted(True) \
    #             .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
    #             .add_passphrase(self.passphrase) \
    #             .init_new(load_if_exists=True)
    #     with self.assertRaises(TypeError):
    #         PrivateKeyBuilder() \
    #             .add_nickname(self.nickname) \
    #             .add_file(self.temporary_private_key_file_name) \
    #             .add_size(self.size) \
    #             .add_public_exponent(self.public_exponent) \
    #             .add_encrypted(False) \
    #             .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
    #             .add_passphrase(self.passphrase) \
    #             .init_new(load_if_exists=True)
    #     with self.assertRaises(RuntimeError):
    #         PrivateKeyBuilder() \
    #             .add_nickname(self.nickname) \
    #             .add_file(self.temporary_private_key_file_name) \
    #             .add_size(self.size) \
    #             .add_public_exponent(self.public_exponent) \
    #             .add_encrypted(True) \
    #             .add_encryption_algorithm(serialization.NoEncryption()) \
    #             .add_passphrase(self.passphrase) \
    #             .init_new(load_if_exists=True)
    #
    # #
    # # Test init_with_llo()
    # #
    #
    # def test_with_llo(self):
    #     llo = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_size(self.size) \
    #         .add_public_exponent(self.public_exponent) \
    #         .add_encrypted(True) \
    #         .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
    #         .add_passphrase(self.passphrase) \
    #         .init_new() \
    #         .llo
    #     private_key = PrivateKeyBuilder() \
    #         .add_nickname(self.nickname) \
    #         .add_llo(llo) \
    #         .add_file(self.temporary_private_key_file_name) \
    #         .add_encrypted(True) \
    #         .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
    #         .add_passphrase(self.passphrase) \
    #         .init_with_llo()
    #     self._test_private_key(
    #         private_key,
    #         nickname=self.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == llo.public_key().public_numbers().e,
    #             lambda x: x.private_numbers().p == llo.private_numbers().p,
    #             lambda x: x.private_numbers().q == llo.private_numbers().q,
    #             lambda x: x.private_numbers().d == llo.private_numbers().d,
    #             lambda x: x.private_numbers().dmp1 == llo.private_numbers().dmp1,
    #             lambda x: x.private_numbers().dmq1 == llo.private_numbers().dmq1,
    #             lambda x: x.private_numbers().iqmp == llo.private_numbers().iqmp,
    #         ]),
    #         file=self.temporary_private_key_file_name,
    #         size=llo.key_size,
    #         public_modulus=llo.public_key().public_numbers().n,
    #         public_exponent=llo.public_key().public_numbers().e,
    #         public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #
    # #
    # # Test reset()
    # #
    #
    # def test_reset(self):
    #     builder = PrivateKeyBuilder(
    #         nickname=self.nickname,
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_exponent=self.public_exponent,
    #         encrypted=True,
    #         encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase.lookup().encode()),
    #         passphrase=self.passphrase
    #     )
    #     self._test_builder(
    #         builder,
    #         nickname=self.nickname,
    #         llo=(TT.NONE,),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_exponent=self.public_exponent,
    #         encrypted=(TT.TRUE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
    #         passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
    #     )
    #     builder.reset()
    #     self._test_builder(
    #         builder,
    #         nickname=(TT.NONE,),
    #         llo=(TT.NONE,),
    #         file=(TT.NONE,),
    #         size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
    #         public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
    #         encrypted=(TT.FALSE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
    #         passphrase=(TT.NONE,)
    #     )
    #     builder = PrivateKeyBuilder(
    #         nickname=self.nickname,
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_exponent=self.public_exponent,
    #         encrypted=False
    #     )
    #     self._test_builder(
    #         builder,
    #         nickname=self.nickname,
    #         llo=(TT.NONE,),
    #         file=self.temporary_private_key_file_name,
    #         size=self.size,
    #         public_exponent=self.public_exponent,
    #         encrypted=(TT.FALSE,),
    #         encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
    #         passphrase=(TT.NONE,)
    #     )
