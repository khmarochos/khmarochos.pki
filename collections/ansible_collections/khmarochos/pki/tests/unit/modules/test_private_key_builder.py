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
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key_builder import PrivateKeyBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase_builder import PassphraseBuilder
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderTestType as TT
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderCheckList
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import AbstractBuilderTest


class TestPrivateKeyBuilder(unittest.TestCase, AbstractBuilderTest):

    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler(sys.stdout)])

    def setUp(self) -> None:
        self.nickname = self.random_string(length=8, character_set='abcdefghijklmnopqrstuvwxyz')
        self.temporary_private_key_file = tempfile.NamedTemporaryFile()
        self.temporary_private_key_file_name = self.temporary_private_key_file.name
        self.temporary_passphrase_file = tempfile.NamedTemporaryFile()
        self.temporary_passphrase_file_name = self.temporary_passphrase_file.name
        self.size = 512
        if self.size == Constants.DEFAULT_PRIVATE_KEY_SIZE:
            raise RuntimeError(f"The custom size ({self.size}) "
                               "must be different from "
                               f"the default one ({Constants.DEFAULT_PRIVATE_KEY_SIZE})")
        self.public_exponent = 0b11
        if self.public_exponent == Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT:
            raise RuntimeError(f"The custom public exponent ({self.public_exponent}) "
                               "must be different from "
                               f"the default one ({Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT})")
        self.passphrase = PassphraseBuilder() \
            .add_file(self.temporary_passphrase_file_name) \
            .add_random(True) \
            .init_with_random()

    def tearDown(self) -> None:
        self.temporary_private_key_file.close()
        self.temporary_passphrase_file.close()

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
            object_to_test=_builder,
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

    #
    # Test parametrization
    #

    # Test parameters passed to the constructor

    def test_parameters_passed_to_constructor(self):
        builder = PrivateKeyBuilder(
            nickname=self.nickname,
            llo=None,
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_exponent=self.public_exponent,
            encrypted=True,
            encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase.lookup().encode()),
            passphrase=self.passphrase
        )
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_exponent=self.public_exponent,
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )
        private_key = builder.init_new()
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_modulus=(TT.LAMBDA, lambda x: x > 0),
            public_exponent=self.public_exponent,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )

    def test_parameters_passed_to_constructor_with_default_values(self):
        builder = PrivateKeyBuilder(
            nickname=self.nickname,
            file=self.temporary_private_key_file_name,
        )
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.temporary_private_key_file_name,
            size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
            public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
            encrypted=(TT.FALSE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
            passphrase=(TT.NONE,)
        )
        private_key = builder.init_new()
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
            file=self.temporary_private_key_file_name,
            size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
            public_modulus=(TT.LAMBDA, lambda x: x > 0),
            public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.FALSE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
            passphrase=(TT.NONE,)
        )

    # Test parameters added at runtime

    def test_parameters_added_at_runtime(self):
        builder = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_size(self.size) \
            .add_public_exponent(self.public_exponent) \
            .add_encrypted(True) \
            .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
            .add_passphrase(self.passphrase)
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_exponent=self.public_exponent,
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )
        private_key = builder.init_new()
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_modulus=(TT.LAMBDA, lambda x: x > 0),
            public_exponent=self.public_exponent,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )

    def test_parameters_added_at_runtime_with_default_values(self):
        builder = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name)
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.temporary_private_key_file_name,
            size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
            public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
            encrypted=(TT.FALSE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
            passphrase=(TT.NONE,)
        )
        private_key = builder.init_new()
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
            file=self.temporary_private_key_file_name,
            size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
            public_modulus=(TT.LAMBDA, lambda x: x > 0),
            public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.FALSE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
            passphrase=(TT.NONE,)
        )

    # Test parameters passed with the final call

    def test_parameters_passed_with_final_call(self):
        private_key = PrivateKeyBuilder() \
            .init_new(
            nickname=self.nickname,
            file=self.temporary_private_key_file_name,
            encrypted=True,
            passphrase=self.passphrase,
            size=self.size,
            public_exponent=self.public_exponent,
            encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase.lookup().encode())
        )
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_modulus=(TT.LAMBDA, lambda x: x > 0),
            public_exponent=self.public_exponent,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )

    def test_parameters_passed_with_final_call_with_default_values(self):
        private_key = PrivateKeyBuilder() \
            .init_new(
            nickname=self.nickname,
            file=self.temporary_private_key_file_name
        )
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
            file=self.temporary_private_key_file_name,
            size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
            public_modulus=(TT.LAMBDA, lambda x: x > 0),
            public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.FALSE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
            passphrase=(TT.NONE,)
        )

    #
    # Test init_with_file()
    #

    def test_with_file_non_existent(self):
        temporary_directory = tempfile.TemporaryDirectory()
        non_existent_file_name = f"{temporary_directory.name}/{self.nickname}"
        if os.path.exists(non_existent_file_name):
            raise RuntimeError(f"The file {non_existent_file_name} exists")
        temporary_directory.cleanup()
        with self.assertRaises(FileNotFoundError):
            PrivateKeyBuilder() \
                .add_nickname(self.nickname) \
                .add_file(non_existent_file_name) \
                .init_with_file()

    def test_with_file_existent_and_encrypted(self):
        private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_size(self.size) \
            .add_public_exponent(self.public_exponent) \
            .add_encrypted(True) \
            .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
            .add_passphrase(self.passphrase) \
            .init_new()
        private_key_saved_llo = private_key.llo
        private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_encrypted(True) \
            .add_passphrase(self.passphrase) \
            .init_with_file()
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_modulus=private_key_saved_llo.public_key().public_numbers().n,
            public_exponent=self.public_exponent,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )

    def test_with_file_existent_and_not_encrypted(self):
        private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_size(self.size) \
            .add_public_exponent(self.public_exponent) \
            .add_encrypted(False) \
            .init_new()
        private_key_saved_llo = private_key.llo
        private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .init_with_file()
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_modulus=private_key_saved_llo.public_key().public_numbers().n,
            public_exponent=self.public_exponent,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.FALSE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
            passphrase=(TT.NONE,)
        )

    #
    # Test init_new()
    #

    def test_loading_if_exists_and_encrypted(self):
        private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_size(self.size) \
            .add_public_exponent(self.public_exponent) \
            .add_encrypted(True) \
            .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
            .add_passphrase(self.passphrase) \
            .init_new()
        private_key_saved_llo = private_key.llo
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == private_key_saved_llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == private_key_saved_llo.public_key().public_numbers().e,
                lambda x: x.private_numbers().p == private_key_saved_llo.private_numbers().p,
                lambda x: x.private_numbers().q == private_key_saved_llo.private_numbers().q,
                lambda x: x.private_numbers().d == private_key_saved_llo.private_numbers().d,
                lambda x: x.private_numbers().dmp1 == private_key_saved_llo.private_numbers().dmp1,
                lambda x: x.private_numbers().dmq1 == private_key_saved_llo.private_numbers().dmq1,
                lambda x: x.private_numbers().iqmp == private_key_saved_llo.private_numbers().iqmp,
            ]),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_modulus=private_key_saved_llo.public_key().public_numbers().n,
            public_exponent=self.public_exponent,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )
        private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_size(self.size) \
            .add_public_exponent(self.public_exponent) \
            .add_encrypted(True) \
            .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
            .add_passphrase(self.passphrase) \
            .init_new(load_if_exists=True)
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == private_key_saved_llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == private_key_saved_llo.public_key().public_numbers().e,
                lambda x: x.private_numbers().p == private_key_saved_llo.private_numbers().p,
                lambda x: x.private_numbers().q == private_key_saved_llo.private_numbers().q,
                lambda x: x.private_numbers().d == private_key_saved_llo.private_numbers().d,
                lambda x: x.private_numbers().dmp1 == private_key_saved_llo.private_numbers().dmp1,
                lambda x: x.private_numbers().dmq1 == private_key_saved_llo.private_numbers().dmq1,
                lambda x: x.private_numbers().iqmp == private_key_saved_llo.private_numbers().iqmp,
            ]),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_modulus=private_key_saved_llo.public_key().public_numbers().n,
            public_exponent=self.public_exponent,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )

    def test_loading_if_exists_and_not_encrypted(self):
        private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_size(self.size) \
            .add_public_exponent(self.public_exponent) \
            .add_encrypted(False) \
            .init_new()
        private_key_saved_llo = private_key.llo
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == private_key_saved_llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == private_key_saved_llo.public_key().public_numbers().e,
                lambda x: x.private_numbers().p == private_key_saved_llo.private_numbers().p,
                lambda x: x.private_numbers().q == private_key_saved_llo.private_numbers().q,
                lambda x: x.private_numbers().d == private_key_saved_llo.private_numbers().d,
                lambda x: x.private_numbers().dmp1 == private_key_saved_llo.private_numbers().dmp1,
                lambda x: x.private_numbers().dmq1 == private_key_saved_llo.private_numbers().dmq1,
                lambda x: x.private_numbers().iqmp == private_key_saved_llo.private_numbers().iqmp,
            ]),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_modulus=private_key_saved_llo.public_key().public_numbers().n,
            public_exponent=self.public_exponent,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.FALSE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
            passphrase=(TT.NONE,)
        )
        private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_size(self.size) \
            .add_public_exponent(self.public_exponent) \
            .add_encrypted(False) \
            .add_encryption_algorithm(serialization.NoEncryption()) \
            .init_new(load_if_exists=True)
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == private_key_saved_llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == private_key_saved_llo.public_key().public_numbers().e,
                lambda x: x.private_numbers().p == private_key_saved_llo.private_numbers().p,
                lambda x: x.private_numbers().q == private_key_saved_llo.private_numbers().q,
                lambda x: x.private_numbers().d == private_key_saved_llo.private_numbers().d,
                lambda x: x.private_numbers().dmp1 == private_key_saved_llo.private_numbers().dmp1,
                lambda x: x.private_numbers().dmq1 == private_key_saved_llo.private_numbers().dmq1,
                lambda x: x.private_numbers().iqmp == private_key_saved_llo.private_numbers().iqmp,
            ]),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_modulus=private_key_saved_llo.public_key().public_numbers().n,
            public_exponent=self.public_exponent,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.FALSE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
            passphrase=(TT.NONE,)
        )

    def test_not_loading_if_exists_with_mismatches(self):
        private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_size(self.size) \
            .add_public_exponent(self.public_exponent) \
            .add_encrypted(True) \
            .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
            .add_passphrase(self.passphrase) \
            .init_new()
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, rsa.RSAPrivateKey),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_modulus=(TT.LAMBDA, lambda x: x > 0),
            public_exponent=self.public_exponent,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )
        with self.assertRaises(RuntimeError):
            PrivateKeyBuilder() \
                .add_nickname(self.nickname) \
                .add_file(self.temporary_private_key_file_name) \
                .add_size(Constants.DEFAULT_PRIVATE_KEY_SIZE) \
                .add_public_exponent(self.public_exponent) \
                .add_encrypted(True) \
                .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
                .add_passphrase(self.passphrase) \
                .init_new(load_if_exists=True)
        with self.assertRaises(RuntimeError):
            PrivateKeyBuilder() \
                .add_nickname(self.nickname) \
                .add_file(self.temporary_private_key_file_name) \
                .add_size(self.size) \
                .add_public_exponent(Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT) \
                .add_encrypted(True) \
                .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
                .add_passphrase(self.passphrase) \
                .init_new(load_if_exists=True)
        with self.assertRaises(TypeError):
            PrivateKeyBuilder() \
                .add_nickname(self.nickname) \
                .add_file(self.temporary_private_key_file_name) \
                .add_size(self.size) \
                .add_public_exponent(self.public_exponent) \
                .add_encrypted(False) \
                .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
                .add_passphrase(self.passphrase) \
                .init_new(load_if_exists=True)
        with self.assertRaises(RuntimeError):
            PrivateKeyBuilder() \
                .add_nickname(self.nickname) \
                .add_file(self.temporary_private_key_file_name) \
                .add_size(self.size) \
                .add_public_exponent(self.public_exponent) \
                .add_encrypted(True) \
                .add_encryption_algorithm(serialization.NoEncryption()) \
                .add_passphrase(self.passphrase) \
                .init_new(load_if_exists=True)

    #
    # Test init_with_llo()
    #

    def test_with_llo(self):
        llo = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_size(self.size) \
            .add_public_exponent(self.public_exponent) \
            .add_encrypted(True) \
            .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
            .add_passphrase(self.passphrase) \
            .init_new() \
            .llo
        private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_llo(llo) \
            .add_file(self.temporary_private_key_file_name) \
            .add_encrypted(True) \
            .add_encryption_algorithm(serialization.BestAvailableEncryption(self.passphrase.lookup().encode())) \
            .add_passphrase(self.passphrase) \
            .init_with_llo()
        self._test_private_key(
            private_key,
            nickname=self.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == llo.public_key().public_numbers().e,
                lambda x: x.private_numbers().p == llo.private_numbers().p,
                lambda x: x.private_numbers().q == llo.private_numbers().q,
                lambda x: x.private_numbers().d == llo.private_numbers().d,
                lambda x: x.private_numbers().dmp1 == llo.private_numbers().dmp1,
                lambda x: x.private_numbers().dmq1 == llo.private_numbers().dmq1,
                lambda x: x.private_numbers().iqmp == llo.private_numbers().iqmp,
            ]),
            file=self.temporary_private_key_file_name,
            size=llo.key_size,
            public_modulus=llo.public_key().public_numbers().n,
            public_exponent=llo.public_key().public_numbers().e,
            public_key=(TT.ISINSTANCE, rsa.RSAPublicKey),
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )

    #
    # Test reset()
    #

    def test_reset(self):
        builder = PrivateKeyBuilder(
            nickname=self.nickname,
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_exponent=self.public_exponent,
            encrypted=True,
            encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase.lookup().encode()),
            passphrase=self.passphrase
        )
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_exponent=self.public_exponent,
            encrypted=(TT.TRUE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.BestAvailableEncryption),
            passphrase=(TT.LAMBDA, lambda x: x.lookup() == self.passphrase.lookup())
        )
        builder.reset()
        self._test_builder(
            builder,
            nickname=(TT.NONE,),
            llo=(TT.NONE,),
            file=(TT.NONE,),
            size=Constants.DEFAULT_PRIVATE_KEY_SIZE,
            public_exponent=Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT,
            encrypted=(TT.FALSE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
            passphrase=(TT.NONE,)
        )
        builder = PrivateKeyBuilder(
            nickname=self.nickname,
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_exponent=self.public_exponent,
            encrypted=False
        )
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.temporary_private_key_file_name,
            size=self.size,
            public_exponent=self.public_exponent,
            encrypted=(TT.FALSE,),
            encryption_algorithm=(TT.ISINSTANCE, serialization.NoEncryption),
            passphrase=(TT.NONE,)
        )
