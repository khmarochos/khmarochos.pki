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
import sys
import unittest
import tempfile
import logging

import cryptography.x509
from cryptography import x509
from cryptography.hazmat.primitives._serialization import Encoding

from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import \
    CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request_builder import \
    CertificateSigningRequestBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase_builder import PassphraseBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key_builder import PrivateKeyBuilder
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderTestType as TT
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderCheckList
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import AbstractBuilderTest


class TestCertificateSigningRequestBuilder(unittest.TestCase, AbstractBuilderTest):

    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler(sys.stdout)])

    def setUp(self) -> None:
        self.nickname = self.random_string(length=8, character_set='abcdefghijklmnopqrstuvwxyz')
        self.certificate_signing_request_file = tempfile.NamedTemporaryFile()
        self.certificate_signing_request_file_name = self.certificate_signing_request_file.name
        self.temporary_private_key_file = tempfile.NamedTemporaryFile()
        self.temporary_private_key_file_name = self.temporary_private_key_file.name
        self.temporary_passphrase_file = tempfile.NamedTemporaryFile()
        self.temporary_passphrase_file_name = self.temporary_passphrase_file.name
        self.subject = CertificateSigningRequestBuilder.compose_subject(
            country_name='PL',
            state_or_province_name='Malopolskie',
            locality_name='Krakow',
            organization_name='TUCHA SPOLKA Z OGRANICZONA ODPOWIEDZIALNOSCIA',
            organizational_unit_name='Security Service',
            email_address='security@kloudster.com',
            common_name='security.kloudster.com'
        )
        self.alternativeNames = ['alpha.local', 'bravo.local', 'charlie.local']
        self.extra_extensions = []
        self.passphrase = PassphraseBuilder() \
            .add_file(self.temporary_passphrase_file_name) \
            .add_random(True) \
            .init_with_random()
        self.private_key = PrivateKeyBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.temporary_private_key_file_name) \
            .add_passphrase(self.passphrase) \
            .init_new()

    def tearDown(self) -> None:
        self.certificate_signing_request_file.close()
        self.temporary_private_key_file.close()
        self.temporary_passphrase_file.close()

    def _test_builder(
            self,
            builder: BuilderCheckList[CertificateSigningRequestBuilder],
            nickname: BuilderCheckList[str],
            llo: BuilderCheckList[x509.CertificateSigningRequest],
            file: BuilderCheckList[str],
            certificate_type: BuilderCheckList[CertificateTypes],
            private_key: BuilderCheckList[PrivateKey],
            subject: BuilderCheckList[x509.name.Name],
            alternative_names: BuilderCheckList[list],
            extra_extensions: BuilderCheckList[list]
    ):
        self._test_object(
            _object_to_test=builder,
            nickname=nickname,
            llo=llo,
            file=file,
            certificate_type=certificate_type,
            private_key=private_key,
            subject=subject,
            alternative_names=alternative_names,
            extra_extensions=extra_extensions
        )

    def _test_certificate_signing_request(
            self,
            certificate_signing_request: CertificateSigningRequest,
            nickname: BuilderCheckList[str],
            llo: BuilderCheckList[x509.CertificateSigningRequest],
            file: BuilderCheckList[str],
            certificate_type: BuilderCheckList[CertificateTypes],
            private_key: BuilderCheckList[PrivateKey],
            subject: BuilderCheckList[x509.name.Name],
            alternative_names: BuilderCheckList[list],
            extra_extensions: BuilderCheckList[list]
    ):
        self._test_object(
            _object_to_test=certificate_signing_request,
            nickname=nickname,
            llo=llo,
            file=file,
            certificate_type=certificate_type,
            private_key=private_key,
            subject=subject,
            alternative_names=alternative_names,
            extra_extensions=extra_extensions
        )

    #
    # Test parametrization
    #

    # Test parameters passed to the constructor

    def test_parameters_passed_to_constructor(self):
        builder = CertificateSigningRequestBuilder(
            nickname=self.nickname,
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=self.private_key,
            subject=self.subject,
            alternative_names=self.alternativeNames,
            extra_extensions=self.extra_extensions
        )
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, lambda x: x.public_modulus == self.private_key.public_modulus),
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=[self.extra_extensions]
        )
        certificate_signing_request = builder.init_new()
        self._test_certificate_signing_request(
            certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, x509.CertificateSigningRequest),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, lambda x: x.public_modulus == self.private_key.public_modulus),
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=[self.extra_extensions]
        )

    def test_parameters_passed_to_constructor_with_default_values(self):
        builder = CertificateSigningRequestBuilder(
            nickname=self.nickname,
            file=self.certificate_signing_request_file_name,
            private_key=self.private_key,
            subject=self.subject
        )
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, lambda x: x.public_modulus == self.private_key.public_modulus),
            subject=self.subject,
            alternative_names=(TT.NONE,),
            extra_extensions=(TT.NONE,)
        )
        certificate_signing_request = builder.init_new()
        self._test_certificate_signing_request(
            certificate_signing_request=certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, x509.CertificateSigningRequest),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=self.private_key,
            subject=self.subject,
            alternative_names=[],
            extra_extensions=[]
        )

    # Test parameters added at runtime

    def test_parameters_added_at_runtime(self):
        builder = CertificateSigningRequestBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.certificate_signing_request_file_name) \
            .add_certificate_type(CertificateTypes.CLIENT) \
            .add_private_key(self.private_key) \
            .add_subject(self.subject) \
            .add_alternative_names(self.alternativeNames) \
            .add_extra_extensions(self.extra_extensions)
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, lambda x: x.public_modulus == self.private_key.public_modulus),
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=[self.extra_extensions]
        )
        certificate_signing_request = builder.init_new()
        self._test_certificate_signing_request(
            certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, x509.CertificateSigningRequest),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, lambda x: x.public_modulus == self.private_key.public_modulus),
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=[self.extra_extensions]
        )

    def test_parameters_added_at_runtime_with_default_values(self):
        builder = CertificateSigningRequestBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.certificate_signing_request_file_name) \
            .add_private_key(self.private_key) \
            .add_subject(self.subject)
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, lambda x: x.public_modulus == self.private_key.public_modulus),
            subject=self.subject,
            alternative_names=(TT.NONE,),
            extra_extensions=(TT.NONE,)
        )
        certificate_signing_request = builder.init_new()
        self._test_certificate_signing_request(
            certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, x509.CertificateSigningRequest),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=self.private_key,
            subject=self.subject,
            alternative_names=[],
            extra_extensions=[]
        )

    def test_parameters_passed_with_final_call(self):
        certificate_signing_request = CertificateSigningRequestBuilder() \
            .init_new(
                nickname=self.nickname,
                file=self.certificate_signing_request_file_name,
                certificate_type=CertificateTypes.CLIENT,
                private_key=self.private_key,
                subject=self.subject,
                alternative_names=self.alternativeNames,
                extra_extensions=self.extra_extensions
            )
        self._test_certificate_signing_request(
            certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, x509.CertificateSigningRequest),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, lambda x: x.public_modulus == self.private_key.public_modulus),
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=[self.extra_extensions]
        )

    def test_parameters_passed_with_final_call_with_default_values(self):
        certificate_signing_request = CertificateSigningRequestBuilder() \
            .init_new(
                nickname=self.nickname,
                file=self.certificate_signing_request_file_name,
                private_key=self.private_key,
                subject=self.subject
            )
        self._test_certificate_signing_request(
            certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, x509.CertificateSigningRequest),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=self.private_key,
            subject=self.subject,
            alternative_names=[],
            extra_extensions=[]
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
            CertificateSigningRequestBuilder() \
                .add_nickname(self.nickname) \
                .add_file(non_existent_file_name) \
                .add_private_key(self.private_key) \
                .init_with_file()

    def test_with_file_existent(self):
        CertificateSigningRequestBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.certificate_signing_request_file_name) \
            .add_certificate_type(CertificateTypes.CLIENT) \
            .add_private_key(self.private_key) \
            .add_subject(self.subject) \
            .add_alternative_names(self.alternativeNames) \
            .init_new()
        certificate_signing_request = CertificateSigningRequestBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.certificate_signing_request_file_name) \
            .add_private_key(self.private_key) \
            .init_with_file()
        self._test_certificate_signing_request(
            certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.ISINSTANCE, x509.CertificateSigningRequest),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=self.private_key,
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=[]
        )

    #
    # Test init_new()
    #

    def test_loading_if_exists(self):
        certificate_signing_request = CertificateSigningRequestBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.certificate_signing_request_file_name) \
            .add_certificate_type(CertificateTypes.CLIENT) \
            .add_private_key(self.private_key) \
            .add_subject(self.subject) \
            .add_alternative_names(self.alternativeNames) \
            .init_new()
        certificate_signing_request_saved_llo = certificate_signing_request.llo
        self._test_certificate_signing_request(
            certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_bytes(Encoding.PEM) == certificate_signing_request_saved_llo.public_bytes(Encoding.PEM),
                lambda x: x.public_bytes(Encoding.DER) == certificate_signing_request_saved_llo.public_bytes(Encoding.DER),
                lambda x: x.public_key().public_numbers().n == self.private_key.public_modulus,
                lambda x: x.public_key().public_numbers().e == self.private_key.public_exponent,
            ]),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, [
                lambda x: x.public_modulus == self.private_key.public_modulus,
                lambda x: x.public_exponent == self.private_key.public_exponent
            ]),
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=[]
        )
        certificate_signing_request = CertificateSigningRequestBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.certificate_signing_request_file_name) \
            .add_certificate_type(CertificateTypes.CLIENT) \
            .add_private_key(self.private_key) \
            .add_subject(self.subject) \
            .add_alternative_names(self.alternativeNames) \
            .init_new(load_if_exists=True)
        self._test_certificate_signing_request(
            certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_bytes(Encoding.PEM) == certificate_signing_request_saved_llo.public_bytes(Encoding.PEM),
                lambda x: x.public_bytes(Encoding.DER) == certificate_signing_request_saved_llo.public_bytes(Encoding.DER),
                lambda x: x.public_key().public_numbers().n == self.private_key.public_modulus,
                lambda x: x.public_key().public_numbers().e == self.private_key.public_exponent,
            ]),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, [
                lambda x: x.public_modulus == self.private_key.public_modulus,
                lambda x: x.public_exponent == self.private_key.public_exponent
            ]),
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=[]
        )

    def test_not_loading_if_exists_with_mismatches(self):
        certificate_signing_request = CertificateSigningRequestBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.certificate_signing_request_file_name) \
            .add_certificate_type(CertificateTypes.CLIENT) \
            .add_private_key(self.private_key) \
            .add_subject(self.subject) \
            .add_alternative_names(self.alternativeNames) \
            .init_new()
        certificate_signing_request_saved_llo = certificate_signing_request.llo
        self._test_certificate_signing_request(
            certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_bytes(Encoding.PEM) == certificate_signing_request_saved_llo.public_bytes(Encoding.PEM),
                lambda x: x.public_bytes(Encoding.DER) == certificate_signing_request_saved_llo.public_bytes(Encoding.DER),
                lambda x: x.public_key().public_numbers().n == self.private_key.public_modulus,
                lambda x: x.public_key().public_numbers().e == self.private_key.public_exponent,
            ]),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, [
                lambda x: x.public_modulus == self.private_key.public_modulus,
                lambda x: x.public_exponent == self.private_key.public_exponent
            ]),
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=[]
        )
        with self.assertRaises(RuntimeError):
            CertificateSigningRequestBuilder() \
                .add_nickname(self.nickname) \
                .add_file(self.certificate_signing_request_file_name) \
                .add_certificate_type(CertificateTypes.SERVER) \
                .add_private_key(self.private_key) \
                .add_subject(self.subject) \
                .add_alternative_names(self.alternativeNames) \
                .init_new(load_if_exists=True)
        with self.assertRaises(RuntimeError):
            CertificateSigningRequestBuilder() \
                .add_nickname(self.nickname) \
                .add_file(self.certificate_signing_request_file_name) \
                .add_certificate_type(CertificateTypes.CLIENT) \
                .add_private_key(PrivateKeyBuilder().init_new(nickname=self.random_string(), file='/dev/null')) \
                .add_subject(self.subject) \
                .add_alternative_names(self.alternativeNames) \
                .init_new(load_if_exists=True)
        with self.assertRaises(RuntimeError):
            CertificateSigningRequestBuilder() \
                .add_nickname(self.nickname) \
                .add_file(self.certificate_signing_request_file_name) \
                .add_certificate_type(CertificateTypes.CLIENT) \
                .add_private_key(self.private_key) \
                .add_subject(CertificateSigningRequestBuilder.compose_subject(common_name=self.random_string())) \
                .add_alternative_names(self.alternativeNames) \
                .init_new(load_if_exists=True)
        with self.assertRaises(RuntimeError):
            CertificateSigningRequestBuilder() \
                .add_nickname(self.nickname) \
                .add_file(self.certificate_signing_request_file_name) \
                .add_certificate_type(CertificateTypes.CLIENT) \
                .add_private_key(self.private_key) \
                .add_subject(self.subject) \
                .add_alternative_names([self.random_string(), self.random_string(), self.random_string()]) \
                .init_new(load_if_exists=True)

    def test_with_llo(self):
        llo = CertificateSigningRequestBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.certificate_signing_request_file_name) \
            .add_certificate_type(CertificateTypes.CLIENT) \
            .add_private_key(self.private_key) \
            .add_subject(self.subject) \
            .add_alternative_names(self.alternativeNames) \
            .init_new() \
            .llo
        certificate_signing_request = CertificateSigningRequestBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.certificate_signing_request_file_name) \
            .add_llo(llo) \
            .add_private_key(self.private_key) \
            .init_with_llo()
        self._test_certificate_signing_request(
            certificate_signing_request,
            nickname=self.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == self.private_key.public_modulus,
                lambda x: x.public_key().public_numbers().e == self.private_key.public_exponent,
            ]),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, [
                lambda x: x.public_modulus == self.private_key.public_modulus,
                lambda x: x.public_exponent == self.private_key.public_exponent
            ]),
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=[]
        )

    def test_reset(self):
        builder = CertificateSigningRequestBuilder() \
            .add_nickname(self.nickname) \
            .add_file(self.certificate_signing_request_file_name) \
            .add_private_key(self.private_key) \
            .add_certificate_type(CertificateTypes.CLIENT) \
            .add_subject(self.subject) \
            .add_alternative_names(self.alternativeNames)
        self._test_builder(
            builder,
            nickname=self.nickname,
            llo=(TT.NONE,),
            file=self.certificate_signing_request_file_name,
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.LAMBDA, [
                lambda x: x.public_modulus == self.private_key.public_modulus,
                lambda x: x.public_exponent == self.private_key.public_exponent
            ]),
            subject=self.subject,
            alternative_names=[self.alternativeNames],
            extra_extensions=(TT.NONE,)
        )
        builder.reset()
        self._test_builder(
            builder,
            nickname=(TT.NONE,),
            llo=(TT.NONE,),
            file=(TT.NONE,),
            certificate_type=CertificateTypes.CLIENT,
            private_key=(TT.NONE,),
            subject=(TT.NONE,),
            alternative_names=(TT.NONE,),
            extra_extensions=(TT.NONE,)
        )



