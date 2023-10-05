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

import random
import secrets
import sys
import unittest
import tempfile
import logging

from cryptography import x509

from ansible_collections.khmarochos.pki.plugins.module_utils.certificate import Certificate
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import \
    CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase
from ansible_collections.khmarochos.pki.plugins.module_utils.pki_ca import PKICA
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_builder import CertificateBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request_builder import \
    CertificateSigningRequestBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes, Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key_builder import PrivateKeyBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase_builder import PassphraseBuilder
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderTestType as TT
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderCheckList
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import AbstractBuilderTest


DOMAIN_NAME = 'kloudster.com'
MIN_RANDOM_STRING_LENGTH = 16
MAX_RANDOM_STRING_LENGTH = 32


# noinspection PyProtectedMember
class TestingSet(FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'type': str,
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER
    },
    'nickname': {},
    'nickname_charset': {'default': 'abcdefghijklmnopqrstuvwxyz'},
    'nickname_minimal_length': {'type': int, 'default': 8},
    'nickname_maximal_length': {'type': int, 'default': 32},
    'certificate': {'type': Certificate},
    'certificate_file': {'type': tempfile._TemporaryFileWrapper},
    'certificate_file_name': {},
    'certificate_chain_file': {'type': tempfile._TemporaryFileWrapper},
    'certificate_chain_file_name': {},
    'certificate_signing_request': {'type': CertificateSigningRequest},
    'certificate_signing_request_file': {'type': tempfile._TemporaryFileWrapper},
    'certificate_signing_request_file_name': {},
    'private_key': {'type': PrivateKey},
    'private_key_file': {'type': tempfile._TemporaryFileWrapper},
    'private_key_file_name': {},
    'passphrase': {'type': Passphrase},
    'passphrase_file': {'type': tempfile._TemporaryFileWrapper},
    'passphrase_file_name': {},
    'passphrase_random': {'type': bool, 'default': True},
    'passphrase_length': {'type': int},
    'passphrase_character_set': {'default': 'abcdefghijklmnopqrstuvwxyz'},
    'passphrase_minimal_length': {'type': int, 'default': 8},
    'passphrase_maximal_length': {'type': int, 'default': 32},
    'passphrase_value': {},
    'certificate_type': {'type': CertificateTypes, 'default': CertificateTypes.CLIENT},
    'term': {'type': int, 'default': Constants.DEFAULT_CERTIFICATE_TERM},
    'subject': {'type': x509.name.Name, 'default': CertificateBuilder.compose_subject(
        country_name='PL',
        state_or_province_name='Malopolskie',
        locality_name='Krakow',
        organization_name='TUCHA SPOLKA Z OGRANICZONA ODPOWIEDZIALNOSCIA',
        organizational_unit_name='Security Service',
        email_address=f'security@{DOMAIN_NAME}',
        common_name=f'security.{DOMAIN_NAME}'
    )},
    'alternativeNames': {'type': list, 'default': [
        f'alpha.{DOMAIN_NAME}',
        f'bravo.{DOMAIN_NAME}',
        f'charlie.{DOMAIN_NAME}',
    ]},
    'extra_extensions': {'type': list, 'default': []},
}):

    @staticmethod
    def random_string(
            length: int = random.randrange(MIN_RANDOM_STRING_LENGTH, MAX_RANDOM_STRING_LENGTH),
            character_set: str = Constants.DEFAULT_PASSPHRASE_CHARACTER_SET
    ) -> str:
        return ''.join(secrets.choice(character_set) for _ in range(length))

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        # Generating the nickname
        if self.nickname is None:
            with self.ignore_readonly('nickname'):
                self.nickname = self.random_string(
                    length=random.randint(
                        self.nickname_minimal_length,
                        self.nickname_maximal_length
                    ),
                    character_set=self.nickname_charset
                )

        # Generating the passphrase
        if self.passphrase_file_name is not None:
            raise ValueError('The passphrase_file_name parameter cannot be set manually')
        if self.passphrase_file is None:
            with self.ignore_readonly('passphrase_file'):
                self.passphrase_file = tempfile.NamedTemporaryFile(
                    prefix='f{nickname}.',
                    suffix='.passphrase.txt',
                )
            with self.ignore_readonly('passphrase_file_name'):
                self.passphrase_file_name = self.passphrase_file.name
        passphrase_builder = PassphraseBuilder()
        passphrase_builder.file = self.passphrase_file_name
        passphrase_builder.random = self.passphrase_random
        if self.passphrase_random:
            if self.passphrase_length is None:
                with self.ignore_readonly('passphrase_length'):
                    self.passphrase_length = random.randint(
                        self.passphrase_minimal_length,
                        self.passphrase_maximal_length
                    )
                    if self.passphrase_length == Constants.DEFAULT_PASSPHRASE_LENGTH:
                        if self.passphrase_length -1 >= self.passphrase_minimal_length:
                            self.passphrase_length -= 1
                        elif self.passphrase_length + 1 <= self.passphrase_maximal_length:
                            self.passphrase_length += 1
                        else:
                            raise RuntimeError('Unable to generate a random passphrase length that would differ from '
                                               'the default passphrase length')
            passphrase_builder.character_set = self.passphrase_character_set
            with self.ignore_readonly('passphrase'):
                self.passphrase = passphrase_builder.init_with_random()
        else:
            passphrase_builder.value = self.passphrase_value
            with self.ignore_readonly('passphrase'):
                self.passphrase = passphrase_builder.init_with_value()

        # Generating the private key
        if self.private_key_file_name is not None:
            raise ValueError('The private_key_file_name parameter cannot be set manually')
        if self.private_key_file is None:
            with self.ignore_readonly('private_key_file'):
                self.private_key_file = tempfile.NamedTemporaryFile(
                    prefix=f'{self.nickname}.',
                    suffix='.private_key.pem',
                )
            with self.ignore_readonly('private_key_file_name'):
                self.private_key_file_name = self.private_key_file.name
        private_key_builder = PrivateKeyBuilder()
        private_key_builder.nickname = self.nickname
        private_key_builder.file = self.private_key_file_name
        private_key_builder.passphrase = self.passphrase
        with self.ignore_readonly('private_key'):
            self.private_key = private_key_builder.init_new()

        # Generating the certificate signing request
        if self.certificate_signing_request_file_name is not None:
            raise ValueError('The certificate_signing_request_file_name parameter cannot be set manually')
        if self.certificate_signing_request_file is None:
            with self.ignore_readonly('certificate_signing_request_file'):
                self.certificate_signing_request_file = tempfile.NamedTemporaryFile(
                    prefix=f'{self.nickname}.',
                    suffix='.csr.pem',
                )
            with self.ignore_readonly('certificate_signing_request_file_name'):
                self.certificate_signing_request_file_name = self.certificate_signing_request_file.name
        certificate_signing_request_builder = CertificateSigningRequestBuilder()
        certificate_signing_request_builder.nickname = self.nickname
        certificate_signing_request_builder.file = self.certificate_signing_request_file_name
        certificate_signing_request_builder.certificate_type = self.certificate_type
        certificate_signing_request_builder.private_key = self.private_key
        certificate_signing_request_builder.subject = self.subject
        certificate_signing_request_builder.alternative_names = self.alternativeNames
        certificate_signing_request_builder.extra_extensions = self.extra_extensions
        with self.ignore_readonly('certificate_signing_request'):
            self.certificate_signing_request = certificate_signing_request_builder.init_new()

        # Setting the parameters of the future certificate
        if self.certificate_file_name is not None:
            raise ValueError('The certificate_file_name parameter cannot be set manually')
        if self.certificate_file is None:
            with self.ignore_readonly('certificate_file'):
                self.certificate_file = tempfile.NamedTemporaryFile(
                    prefix=f'{self.nickname}.',
                    suffix='.crt.pem',
                )
        with self.ignore_readonly('certificate_file_name'):
            self.certificate_file_name = self.certificate_file.name
        if self.certificate_chain_file_name is not None:
            raise ValueError('The certificate_chain_file_name parameter cannot be set manually')
        if self.certificate_chain_file is None:
            with self.ignore_readonly('certificate_chain_file'):
                self.certificate_chain_file = tempfile.NamedTemporaryFile(
                    prefix=f'{self.nickname}.',
                    suffix='.chain.crt.pem',
                )
        with self.ignore_readonly('certificate_chain_file_name'):
            self.certificate_chain_file_name = self.certificate_chain_file.name

    def __del__(self):
        if self.passphrase_file is not None:
            self.passphrase_file.close()
        if self.private_key_file is not None:
            self.private_key_file.close()
        if self.certificate_signing_request_file is not None:
            self.certificate_signing_request_file.close()
        if self.certificate_file is not None:
            self.certificate_file.close()


# noinspection SpellCheckingInspection
class TestCertificateBuilder(unittest.TestCase, AbstractBuilderTest):

    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler(sys.stdout)])

    def setUp(self) -> None:
        self.testing_set = TestingSet()

    def tearDown(self) -> None:
        del self.testing_set

    def _test_builder(
            self,
            _builder: BuilderCheckList[CertificateSigningRequestBuilder],
            nickname: BuilderCheckList[str],
            llo: BuilderCheckList[x509.CertificateSigningRequest],
            file: BuilderCheckList[str],
            chain_file: BuilderCheckList[str],
            term: BuilderCheckList[int],
            ca: BuilderCheckList[PKICA],
            certificate_type: BuilderCheckList[CertificateTypes],
            issuer_private_key: BuilderCheckList[PrivateKey],
            issuer_subject: BuilderCheckList[x509.name.Name],
            private_key: BuilderCheckList[PrivateKey],
            subject: BuilderCheckList[x509.name.Name],
            alternative_names: BuilderCheckList[list],
            extra_extensions: BuilderCheckList[list],
            certificate_signing_request: BuilderCheckList[CertificateSigningRequest],
    ):
        self._test_object(
            _object_to_test=_builder,
            nickname=nickname,
            llo=llo,
            file=file,
            chain_file=chain_file,
            term=term,
            ca=ca,
            certificate_type=certificate_type,
            issuer_private_key=issuer_private_key,
            issuer_subject=issuer_subject,
            private_key=private_key,
            subject=subject,
            alternative_names=alternative_names,
            extra_extensions=extra_extensions,
            certificate_signing_request=certificate_signing_request,
        )

    def _test_certificate(
        self,
        _certificate: BuilderCheckList[Certificate],
        nickname: BuilderCheckList[str],
        llo: BuilderCheckList[x509.Certificate],
        file: BuilderCheckList[str],
        chain_file: BuilderCheckList[str],
        term: BuilderCheckList[int],
        ca: BuilderCheckList[PKICA],
        certificate_type: BuilderCheckList[CertificateTypes],
        issuer_private_key: BuilderCheckList[PrivateKey],
        issuer_subject: BuilderCheckList[x509.name.Name],
        private_key: BuilderCheckList[PrivateKey],
        subject: BuilderCheckList[x509.name.Name],
        alternative_names: BuilderCheckList[list],
        extra_extensions: BuilderCheckList[list],
    ):
        self._test_object(
            _object_to_test=_certificate,
            nickname=nickname,
            llo=llo,
            file=file,
            chain_file=chain_file,
            term=term,
            ca=ca,
            certificate_type=certificate_type,
            issuer_private_key=issuer_private_key,
            issuer_subject=issuer_subject,
            private_key=private_key,
            subject=subject,
            alternative_names=alternative_names,
            extra_extensions=extra_extensions,
        )

    #
    # Test parametrization
    #

    # Test parameters passed to the constructor

    def test_parameters_passed_to_constructor(self):
        testset = self.testing_set
        # with self.assertWarns(RuntimeWarning):
        certificate_builder = CertificateBuilder(
            nickname=testset.nickname,
            file=testset.certificate_file_name,
            private_key=testset.private_key,
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=testset.term,
            certificate_signing_request=testset.certificate_signing_request,
        )
        self._test_builder(
            _builder=certificate_builder,
            nickname=testset.nickname,
            llo=(TT.NONE,),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=testset.term,
            ca=(TT.NONE,),
            issuer_private_key=(TT.NONE,),
            issuer_subject=(TT.NONE,),
            private_key=testset.private_key,
            subject=(TT.NONE,),
            alternative_names=(TT.NONE,),
            extra_extensions=(TT.NONE,),
            certificate_signing_request=testset.certificate_signing_request,
        )
        with self.assertWarnsRegex(
                expected_warning=RuntimeWarning,
                expected_regex=r'the certificate signing request supposes a different type'
        ):
            certificate = certificate_builder.sign_csr()
        self._test_certificate(
            _certificate=certificate,
            nickname=self.testing_set.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == testset.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=testset.term,
            ca=(TT.NONE,),
            issuer_private_key=testset.private_key,
            issuer_subject=testset.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[],
        )

    def test_parameters_passed_to_constructor_with_default_values(self):
        testset = self.testing_set
        certificate_builder = CertificateBuilder(
            nickname=testset.nickname,
            file=testset.certificate_file_name,
            private_key=testset.private_key,
            certificate_signing_request=testset.certificate_signing_request
        )
        self._test_builder(
            _builder=certificate_builder,
            nickname=testset.nickname,
            llo=(TT.NONE,),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CLIENT,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=(TT.NONE,),
            issuer_subject=(TT.NONE,),
            private_key=testset.private_key,
            subject=(TT.NONE,),
            alternative_names=(TT.NONE,),
            extra_extensions=(TT.NONE,),
            certificate_signing_request=testset.certificate_signing_request
        )
        certificate = certificate_builder.sign_csr()
        self._test_certificate(
            _certificate=certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == testset.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CLIENT,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=testset.private_key,
            issuer_subject=testset.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[]
        )

    def test_parameters_added_at_runtime(self):
        testset = self.testing_set
        certificate_builder = CertificateBuilder() \
            .add_nickname(testset.nickname) \
            .add_file(testset.certificate_file_name) \
            .add_private_key(testset.private_key) \
            .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
            .add_term(testset.term) \
            .add_certificate_signing_request(testset.certificate_signing_request)
        self._test_builder(
            _builder=certificate_builder,
            nickname=testset.nickname,
            llo=(TT.NONE,),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=testset.term,
            ca=(TT.NONE,),
            issuer_private_key=(TT.NONE,),
            issuer_subject=(TT.NONE,),
            private_key=testset.private_key,
            subject=(TT.NONE,),
            alternative_names=(TT.NONE,),
            extra_extensions=(TT.NONE,),
            certificate_signing_request=testset.certificate_signing_request,
        )
        with self.assertWarnsRegex(
            expected_warning=RuntimeWarning,
            expected_regex=r'the certificate signing request supposes a different type'
        ):
            certificate = certificate_builder.sign_csr()
        self._test_certificate(
            _certificate=certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == testset.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=testset.term,
            ca=(TT.NONE,),
            issuer_private_key=testset.private_key,
            issuer_subject=testset.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[]
        )

    def test_parameters_added_at_runtime_with_default_values(self):
        testset = self.testing_set
        certificate_builder = CertificateBuilder() \
            .add_nickname(testset.nickname) \
            .add_file(testset.certificate_file_name) \
            .add_private_key(testset.private_key) \
            .add_certificate_signing_request(testset.certificate_signing_request)
        self._test_builder(
            _builder=certificate_builder,
            nickname=testset.nickname,
            llo=(TT.NONE,),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CLIENT,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=(TT.NONE,),
            issuer_subject=(TT.NONE,),
            private_key=testset.private_key,
            subject=(TT.NONE,),
            alternative_names=(TT.NONE,),
            extra_extensions=(TT.NONE,),
            certificate_signing_request=testset.certificate_signing_request,
        )
        certificate = certificate_builder.sign_csr()
        self._test_certificate(
            _certificate=certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == testset.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CLIENT,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=testset.private_key,
            issuer_subject=testset.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[]
        )

    def test_parameters_passed_with_final_call(self):
        testset = self.testing_set
        with self.assertWarnsRegex(
            expected_warning=RuntimeWarning,
            expected_regex=r'the certificate signing request supposes a different type'
        ):
            certificate = CertificateBuilder() \
                .sign_csr(
                    nickname=testset.nickname,
                    file=testset.certificate_file_name,
                    private_key=testset.private_key,
                    certificate_type=CertificateTypes.CA_INTERMEDIATE,
                    term=testset.term,
                    certificate_signing_request=testset.certificate_signing_request
                )
        self._test_certificate(
            _certificate=certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == testset.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=testset.term,
            ca=(TT.NONE,),
            issuer_private_key=testset.private_key,
            issuer_subject=testset.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[]
        )

    def test_parameters_passed_with_final_call_with_default_values(self):
        testset = self.testing_set
        certificate = CertificateBuilder() \
            .sign_csr(
                nickname=testset.nickname,
                file=testset.certificate_file_name,
                private_key=testset.private_key,
                certificate_signing_request=testset.certificate_signing_request
            )
        self._test_certificate(
            _certificate=certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == testset.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CLIENT,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=testset.private_key,
            issuer_subject=testset.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[]
        )

    def test_sign_csr(self):
        testset = self.testing_set
        with self.assertWarnsRegex(
            expected_warning=RuntimeWarning,
            expected_regex=r'the certificate signing request supposes a different type'
        ):
            certificate = CertificateBuilder() \
                .add_nickname(testset.nickname) \
                .add_file(testset.certificate_file_name) \
                .add_private_key(testset.private_key) \
                .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
                .add_subject(testset.subject) \
                .add_alternative_names(testset.alternativeNames) \
                .add_term(testset.term) \
                .add_certificate_signing_request(testset.certificate_signing_request) \
                .sign_csr()
        self._test_certificate(
            _certificate=certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == testset.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=testset.term,
            ca=(TT.NONE,),
            issuer_private_key=testset.private_key,
            issuer_subject=testset.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[],
        )

    def test_sign_csr_with_default_values(self):
        testset = self.testing_set
        certificate = CertificateBuilder() \
            .add_nickname(testset.nickname) \
            .add_file(testset.certificate_file_name) \
            .add_private_key(testset.private_key) \
            .add_certificate_signing_request(testset.certificate_signing_request) \
            .sign_csr()
        self._test_certificate(
            _certificate=certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == testset.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CLIENT,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=testset.private_key,
            issuer_subject=testset.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[],
        )

    def test_sign_instantly(self):
        testset = self.testing_set
        certificate = CertificateBuilder() \
            .add_nickname(testset.nickname) \
            .add_file(testset.certificate_file_name) \
            .add_private_key(testset.private_key) \
            .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
            .add_subject(testset.subject) \
            .add_alternative_names(testset.alternativeNames) \
            .add_term(testset.term) \
            .sign_instantly()
        self._test_certificate(
            _certificate=certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == testset.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=testset.term,
            ca=(TT.NONE,),
            issuer_private_key=testset.private_key,
            issuer_subject=testset.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[]
        )

    def test_sign_instantly_with_default_values(self):
        testset = self.testing_set
        certificate = CertificateBuilder() \
            .add_nickname(testset.nickname) \
            .add_file(testset.certificate_file_name) \
            .add_private_key(testset.private_key) \
            .add_subject(testset.subject) \
            .sign_instantly()
        self._test_certificate(
            _certificate=certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == testset.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CLIENT,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=testset.private_key,
            issuer_subject=testset.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[],
            extra_extensions=[]
        )

    def test_sign_csr_by_ca(self):
        testset_ca = TestingSet(
            subject=CertificateBuilder.compose_subject(
                country_name='PL',
                state_or_province_name='Malopolskie',
                locality_name='Krakow',
                organization_name='TUCHA SPOLKA Z OGRANICZONA ODPOWIEDZIALNOSCIA',
                organizational_unit_name='Security Service',
                email_address=f'security@{DOMAIN_NAME}',
                common_name='Root CA'
            )
        )
        certificate_ca = CertificateBuilder() \
            .add_nickname(testset_ca.nickname) \
            .add_file(testset_ca.certificate_file_name) \
            .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
            .add_private_key(testset_ca.private_key) \
            .add_subject(testset_ca.subject) \
            .sign_instantly()
        self._test_certificate(
            certificate_ca,
            nickname=testset_ca.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset_ca.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset_ca.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset_ca.subject,
                lambda x: x.issuer == testset_ca.subject,
            ]),
            file=testset_ca.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=testset_ca.private_key,
            issuer_subject=testset_ca.subject,
            private_key=testset_ca.private_key,
            subject=testset_ca.subject,
            alternative_names=[],
            extra_extensions=[]
        )
        testset = self.testing_set
        certificate = CertificateBuilder() \
            .add_nickname(testset.nickname) \
            .add_file(testset.certificate_file_name) \
            .add_chain_file(testset.certificate_chain_file_name) \
            .add_private_key(testset.private_key) \
            .add_certificate_signing_request(testset.certificate_signing_request) \
            .add_issuer_private_key(certificate_ca.private_key) \
            .add_issuer_subject(certificate_ca.subject) \
            .sign_csr()
        self._test_certificate(
            certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == certificate_ca.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=testset.certificate_chain_file_name,
            certificate_type=CertificateTypes.CLIENT,
            term=testset.term,
            ca=(TT.NONE,),
            issuer_private_key=certificate_ca.private_key,
            issuer_subject=certificate_ca.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[]
        )


    def test_sign_instantly_by_ca(self):
        testset_ca = TestingSet(
            subject=CertificateBuilder.compose_subject(
                country_name='PL',
                state_or_province_name='Malopolskie',
                locality_name='Krakow',
                organization_name='TUCHA SPOLKA Z OGRANICZONA ODPOWIEDZIALNOSCIA',
                organizational_unit_name='Security Service',
                email_address=f'security@{DOMAIN_NAME}',
                common_name='Root CA'
            )
        )
        certificate_ca = CertificateBuilder() \
            .add_nickname(testset_ca.nickname) \
            .add_file(testset_ca.certificate_file_name) \
            .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
            .add_private_key(testset_ca.private_key) \
            .add_subject(testset_ca.subject) \
            .sign_instantly()
        self._test_certificate(
            certificate_ca,
            nickname=testset_ca.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset_ca.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset_ca.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset_ca.subject,
                lambda x: x.issuer == testset_ca.subject,
            ]),
            file=testset_ca.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=testset_ca.private_key,
            issuer_subject=testset_ca.subject,
            private_key=testset_ca.private_key,
            subject=testset_ca.subject,
            alternative_names=[],
            extra_extensions=[]
        )
        testset = self.testing_set
        certificate = CertificateBuilder() \
            .add_nickname(testset.nickname) \
            .add_file(testset.certificate_file_name) \
            .add_chain_file(testset.certificate_chain_file_name) \
            .add_private_key(testset.private_key) \
            .add_issuer_private_key(certificate_ca.private_key) \
            .add_issuer_subject(certificate_ca.subject) \
            .add_certificate_type(CertificateTypes.CLIENT) \
            .add_subject(testset.subject) \
            .add_alternative_names(testset.alternativeNames) \
            .add_term(testset.term) \
            .sign_instantly()
        self._test_certificate(
            certificate,
            nickname=testset.nickname,
            llo=(TT.LAMBDA, [
                lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
                lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
                lambda x: x.subject == testset.subject,
                lambda x: x.issuer == certificate_ca.subject,
            ]),
            file=testset.certificate_file_name,
            chain_file=testset.certificate_chain_file_name,
            certificate_type=CertificateTypes.CLIENT,
            term=testset.term,
            ca=(TT.NONE,),
            issuer_private_key=certificate_ca.private_key,
            issuer_subject=certificate_ca.subject,
            private_key=testset.private_key,
            subject=testset.subject,
            alternative_names=[testset.alternativeNames],
            extra_extensions=[]
        )

    def test_reset(self, **kwargs):
        testset = self.testing_set
        certificate_builder = CertificateBuilder()
        self._test_builder(
            _builder=certificate_builder,
            nickname=(TT.NONE,),
            llo=(TT.NONE,),
            file=(TT.NONE,),
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CLIENT,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=(TT.NONE,),
            issuer_subject=(TT.NONE,),
            private_key=(TT.NONE,),
            subject=(TT.NONE,),
            alternative_names=(TT.NONE,),
            extra_extensions=(TT.NONE,),
            certificate_signing_request=(TT.NONE,)
        )
        certificate_builder = CertificateBuilder() \
            .add_nickname(testset.nickname) \
            .add_file(testset.certificate_file_name) \
            .add_private_key(testset.private_key) \
            .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
            .add_term(testset.term) \
            .add_certificate_signing_request(testset.certificate_signing_request)
        self._test_builder(
            _builder=certificate_builder,
            nickname=testset.nickname,
            llo=(TT.NONE,),
            file=testset.certificate_file_name,
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CA_INTERMEDIATE,
            term=testset.term,
            ca=(TT.NONE,),
            issuer_private_key=(TT.NONE,),
            issuer_subject=(TT.NONE,),
            private_key=testset.private_key,
            subject=(TT.NONE,),
            alternative_names=(TT.NONE,),
            extra_extensions=(TT.NONE,),
            certificate_signing_request=testset.certificate_signing_request
        )
        certificate_builder.reset()
        self._test_builder(
            _builder=certificate_builder,
            nickname=(TT.NONE,),
            llo=(TT.NONE,),
            file=(TT.NONE,),
            chain_file=(TT.NONE,),
            certificate_type=CertificateTypes.CLIENT,
            term=Constants.DEFAULT_CERTIFICATE_TERM,
            ca=(TT.NONE,),
            issuer_private_key=(TT.NONE,),
            issuer_subject=(TT.NONE,),
            private_key=(TT.NONE,),
            subject=(TT.NONE,),
            alternative_names=(TT.NONE,),
            extra_extensions=(TT.NONE,),
            certificate_signing_request=(TT.NONE,)
        )

    # def test(self):
    #
    #     class TestParametrisation(Enum):
    #         CONSTRUCTOR = 'constructor'
    #         RUNTIME = 'runtime'
    #         FINAL_CALL = 'final_call'
    #
    #     class TestParametrisationDefaultValues(Enum):
    #         DEFAULT_VALUES = 'default_values'
    #         NON_DEFAULT_VALUES = 'non_default_values'
    #
    #     for test_parametrisation in TestParametrisation:
    #         for test_parametrisation_default_values in TestParametrisationDefaultValues:
    #             with self.subTest(
    #                     test_parametrisation=test_parametrisation,
    #                     test_parametrisation_default_values=test_parametrisation_default_values
    #             ):
    #                 nickname = self.random_string(length=8, character_set='abcdefghijklmnopqrstuvwxyz')
    #                 certificate_file = tempfile.NamedTemporaryFile()
    #                 certificate_file_name = certificate_file.name
    #                 certificate_signing_request_file = tempfile.NamedTemporaryFile()
    #                 certificate_signing_request_file_name = certificate_signing_request_file.name
    #                 temporary_private_key_file = tempfile.NamedTemporaryFile()
    #                 temporary_private_key_file_name = temporary_private_key_file.name
    #                 temporary_passphrase_file = tempfile.NamedTemporaryFile()
    #                 temporary_passphrase_file_name = temporary_passphrase_file.name
    #                 term = random.randint(1, 100)
    #                 subject = CertificateBuilder.compose_subject(
    #                     country_name='PL',
    #                     state_or_province_name='Malopolskie',
    #                     locality_name='Krakow',
    #                     organization_name='TUCHA SPOLKA Z OGRANICZONA ODPOWIEDZIALNOSCIA',
    #                     organizational_unit_name='Security Service',
    #                     email_address='security@kloudster.com',
    #                     common_name='security.kloudster.com'
    #                 )
    #                 alternative_names = ['alpha', 'bravo', 'charlie']
    #                 passphrase = PassphraseBuilder() \
    #                     .add_file(temporary_passphrase_file_name) \
    #                     .add_random(True) \
    #                     .init_with_random()
    #                 private_key = PrivateKeyBuilder() \
    #                     .add_nickname(nickname) \
    #                     .add_file(temporary_private_key_file_name) \
    #                     .add_passphrase(passphrase) \
    #                     .init_new()
    #                 certificate_signing_request = CertificateSigningRequestBuilder() \
    #                     .add_nickname(nickname) \
    #                     .add_file(certificate_signing_request_file_name) \
    #                     .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
    #                     .add_private_key(private_key) \
    #                     .add_subject(subject) \
    #                     .add_alternative_names(alternative_names) \
    #                     .init_new()
    #                 if test_parametrisation == TestParametrisation.CONSTRUCTOR: