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

import sys
import unittest
import logging
import yaml
from enum import Enum

from parameterized import parameterized
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
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderTestType as TT, \
    TestingSet, Randomizer
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderCheckList
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import AbstractBuilderTest


# noinspection SpellCheckingInspection
class TestCertificateBuilder(unittest.TestCase, AbstractBuilderTest):

    class TPConfiguring(Enum):
        CONSTRUCTOR = 'passing parameters to the constructor'
        RUNTIME = 'adding parameters at runtime'
        FINAL_CALL = 'passing parameters with the final call'

    class TPValues(Enum):
        DEFAULT = 'using default values'
        DEFINED = 'using defined values'

    class TPRequest(Enum):
        CSR = 'using a certificate signing request'
        INSTANT = 'instantly signing the certificate'

    class TPIssuer(Enum):
        SELF = 'signing the certificate by itself'
        CA_ROOT = 'signing the certificate by a CA'
        CA_INTERMEDIATE_1 = 'signing the certificate by an intermediate CA signed by a root CA'
        CA_INTERMEDIATE_2 = 'signing the certificate by an intermediate CA signed by another intermediate CA'

    class TPInit(Enum):
        NEW = 'creating a new certificate'
        LOAD_LLO = 'load a certificate from x509.Certificate'
        LOAD_FILE = 'load a certificate from a file'

    PARAMETER_SETS = []
    for tp_configuring in list(TPConfiguring):
        for tp_values in list(TPValues):
            for tp_request in list(TPRequest):
                for tp_issuer in list(TPIssuer):
                    PARAMETER_SETS.append((
                        '__'.join((
                            tp_configuring.name,
                            tp_values.name,
                            tp_request.name,
                            tp_issuer.name
                        )),
                        tp_configuring,
                        tp_values,
                        tp_request,
                        tp_issuer
                    ))

    DOMAIN_NAME = 'kloudster.com'

    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler(sys.stdout)])

    # def setUp(self) -> None:
    #     self.testing_set = TestingSet()

    # def tearDown(self) -> None:
    #     del self.testing_set

    def _test_builder(
            self,
            _builder: BuilderCheckList[CertificateBuilder],
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

    @parameterized.expand(PARAMETER_SETS)
    def test_everything(self, name, tp_configuring, tp_values, tp_request, tp_issuer):

        randomizer = Randomizer()

        if tp_issuer in (
                TestCertificateBuilder.TPIssuer.CA_ROOT,
                TestCertificateBuilder.TPIssuer.CA_INTERMEDIATE_1,
                TestCertificateBuilder.TPIssuer.CA_INTERMEDIATE_2
        ):
            testset_ca_root = TestingSet(
                nickname=randomizer,
                passphrase_random=True,
                passphrase_length=randomizer,
                passphrase_character_set=randomizer,
                certificate_type=CertificateTypes.CA_INTERMEDIATE,
                certificate_term=randomizer,
                certificate_subject_common_name='Root CA',
                certificate_alternative_names=[],
                certificate_extra_extensions=[],
            )
            certificate_ca_root = CertificateBuilder(
                nickname=testset_ca_root.nickname,
                file=testset_ca_root.certificate_file_name,
                private_key=testset_ca_root.private_key,
                certificate_type=testset_ca_root.certificate_type,
                term=testset_ca_root.certificate_term,
                certificate_signing_request=testset_ca_root.certificate_signing_request,
            ).sign_csr()
            self._test_certificate(
                _certificate=certificate_ca_root,
                nickname=testset_ca_root.nickname,
                llo=(TT.LAMBDA, [
                    lambda x: x.public_key().public_numbers().n == testset_ca_root.private_key.llo.public_key().public_numbers().n,
                    lambda x: x.public_key().public_numbers().e == testset_ca_root.private_key.llo.public_key().public_numbers().e,
                    lambda x: x.subject == testset_ca_root.certificate_subject,
                    lambda x: x.issuer == testset_ca_root.certificate_subject,
                ]),
                file=testset_ca_root.certificate_file_name,
                chain_file=(TT.NONE,),
                certificate_type=CertificateTypes.CA_INTERMEDIATE,
                term=testset_ca_root.certificate_term,
                ca=(TT.NONE,),
                issuer_private_key=testset_ca_root.private_key,
                issuer_subject=testset_ca_root.certificate_subject,
                private_key=testset_ca_root.private_key,
                subject=testset_ca_root.certificate_subject,
                alternative_names=[testset_ca_root.certificate_alternative_names],
                extra_extensions=[testset_ca_root.certificate_extra_extensions],
            )

        if tp_issuer in (
                TestCertificateBuilder.TPIssuer.CA_INTERMEDIATE_1,
                TestCertificateBuilder.TPIssuer.CA_INTERMEDIATE_2
        ):
            testset_ca_intermediate_1 = TestingSet(
                nickname=randomizer,
                passphrase_random=True,
                passphrase_length=randomizer,
                passphrase_character_set=randomizer,
                certificate_type=CertificateTypes.CA_INTERMEDIATE,
                certificate_term=randomizer,
                certificate_subject_common_name='Intermediate CA (the 1st level)',
                certificate_alternative_names=[],
                certificate_extra_extensions=[],
            )
            certificate_ca_intermediate_1 = CertificateBuilder(
                nickname=testset_ca_intermediate_1.nickname,
                file=testset_ca_intermediate_1.certificate_file_name,
                private_key=testset_ca_intermediate_1.private_key,
                certificate_type=testset_ca_intermediate_1.certificate_type,
                term=testset_ca_root.certificate_term,
                certificate_signing_request=testset_ca_intermediate_1.certificate_signing_request,
                issuer_private_key=testset_ca_root.private_key,
                issuer_subject=testset_ca_root.certificate_subject,
            ).sign_csr()
            self._test_certificate(
                _certificate=certificate_ca_intermediate_1,
                nickname=testset_ca_intermediate_1.nickname,
                llo=(TT.LAMBDA, [
                    lambda x: x.public_key().public_numbers().n == testset_ca_intermediate_1.private_key.llo.public_key().public_numbers().n,
                    lambda x: x.public_key().public_numbers().e == testset_ca_intermediate_1.private_key.llo.public_key().public_numbers().e,
                    lambda x: x.subject == testset_ca_intermediate_1.certificate_subject,
                    lambda x: x.issuer == testset_ca_root.certificate_subject,
                ]),
                file=testset_ca_intermediate_1.certificate_file_name,
                chain_file=(TT.NONE,),
                certificate_type=CertificateTypes.CA_INTERMEDIATE,
                term=testset_ca_root.certificate_term,
                ca=(TT.NONE,),
                issuer_private_key=testset_ca_root.private_key,
                issuer_subject=testset_ca_root.certificate_subject,
                private_key=testset_ca_intermediate_1.private_key,
                subject=testset_ca_intermediate_1.certificate_subject,
                alternative_names=[testset_ca_intermediate_1.certificate_alternative_names],
                extra_extensions=[testset_ca_intermediate_1.certificate_extra_extensions],
            )

        if tp_issuer in (
                TestCertificateBuilder.TPIssuer.CA_INTERMEDIATE_2,
        ):
            testset_ca_intermediate_2 = TestingSet(
                nickname=randomizer,
                passphrase_random=True,
                passphrase_length=randomizer,
                passphrase_character_set=randomizer,
                certificate_type=CertificateTypes.CA_INTERMEDIATE,
                certificate_term=randomizer,
                certificate_subject_common_name='Intermediate CA (the 2nd level)',
                certificate_alternative_names=[],
                certificate_extra_extensions=[],
            )
            certificate_ca_intermediate_2 = CertificateBuilder(
                nickname=testset_ca_intermediate_2.nickname,
                file=testset_ca_intermediate_2.certificate_file_name,
                private_key=testset_ca_intermediate_2.private_key,
                certificate_type=testset_ca_intermediate_2.certificate_type,
                term=testset_ca_root.certificate_term,
                certificate_signing_request=testset_ca_intermediate_2.certificate_signing_request,
                issuer_private_key=testset_ca_intermediate_1.private_key,
                issuer_subject=testset_ca_intermediate_1.certificate_subject,
            ).sign_csr()
            self._test_certificate(
                _certificate=certificate_ca_intermediate_2,
                nickname=testset_ca_intermediate_2.nickname,
                llo=(TT.LAMBDA, [
                    lambda x: x.public_key().public_numbers().n == testset_ca_intermediate_2.private_key.llo.public_key().public_numbers().n,
                    lambda x: x.public_key().public_numbers().e == testset_ca_intermediate_2.private_key.llo.public_key().public_numbers().e,
                    lambda x: x.subject == testset_ca_intermediate_2.certificate_subject,
                    lambda x: x.issuer == testset_ca_intermediate_1.certificate_subject,
                ]),
                file=testset_ca_intermediate_2.certificate_file_name,
                chain_file=(TT.NONE,),
                certificate_type=CertificateTypes.CA_INTERMEDIATE,
                term=testset_ca_root.certificate_term,
                ca=(TT.NONE,),
                issuer_private_key=testset_ca_intermediate_1.private_key,
                issuer_subject=testset_ca_intermediate_1.certificate_subject,
                private_key=testset_ca_intermediate_2.private_key,
                subject=testset_ca_intermediate_2.certificate_subject,
                alternative_names=[testset_ca_intermediate_2.certificate_alternative_names],
                extra_extensions=[testset_ca_intermediate_2.certificate_extra_extensions],
            )

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
        testset_parameters['provided']['testset']['nickname'] = randomizer
        testset_parameters['provided']['testset']['passphrase_random'] = True
        testset_parameters['provided']['testset']['passphrase_length'] = randomizer
        testset_parameters['provided']['testset']['passphrase_character_set'] = randomizer
        testset_parameters['provided']['testset']['certificate_type'] = CertificateTypes.CLIENT
        if tp_values == TestCertificateBuilder.TPValues.DEFINED:
            testset_parameters['provided']['testset']['certificate_term'] = randomizer
            testset_parameters['provided']['testset']['certificate_subject_common_name'] = randomizer
            testset_parameters['provided']['testset']['certificate_alternative_names'] = randomizer
            testset_parameters['provided']['testset']['certificate_extra_extensions'] = []
        elif tp_values == TestCertificateBuilder.TPValues.DEFAULT:
            pass
        else:
            raise ValueError(f'Unexpected tp_values value: {tp_values}')
        if tp_request == TestCertificateBuilder.TPRequest.CSR:
            pass
        elif tp_request == TestCertificateBuilder.TPRequest.INSTANT:
            pass
        if tp_issuer == TestCertificateBuilder.TPIssuer.SELF:
            pass
        elif tp_issuer == TestCertificateBuilder.TPIssuer.CA_ROOT:
            testset_parameters['provided']['testset']['certificate_issuer_private_key'] = testset_ca_root.private_key
            testset_parameters['provided']['testset']['certificate_issuer_subject'] = testset_ca_root.certificate_subject
        elif tp_issuer == TestCertificateBuilder.TPIssuer.CA_INTERMEDIATE_1:
            testset_parameters['provided']['testset']['certificate_issuer_private_key'] = testset_ca_intermediate_1.private_key
            testset_parameters['provided']['testset']['certificate_issuer_subject'] = testset_ca_intermediate_1.certificate_subject
        elif tp_issuer == TestCertificateBuilder.TPIssuer.CA_INTERMEDIATE_2:
            testset_parameters['provided']['testset']['certificate_issuer_private_key'] = testset_ca_intermediate_2.private_key
            testset_parameters['provided']['testset']['certificate_issuer_subject'] = testset_ca_intermediate_2.certificate_subject
        else:
            raise ValueError(f'Unexpected tp_issuer value: {tp_issuer}')

        testset = TestingSet(**testset_parameters['provided']['testset'])

        testset_parameters['provided']['builder']['nickname'] = testset.nickname
        testset_parameters['expected']['builder']['nickname'] = testset.nickname
        testset_parameters['expected']['outcome']['nickname'] = testset.nickname
        testset_parameters['provided']['builder']['file'] = testset.certificate_file_name
        testset_parameters['expected']['builder']['file'] = testset.certificate_file_name
        testset_parameters['expected']['outcome']['file'] = testset.certificate_file_name
        testset_parameters['provided']['builder']['private_key'] = testset.private_key
        testset_parameters['expected']['builder']['private_key'] = testset.private_key
        testset_parameters['expected']['outcome']['private_key'] = testset.private_key
        testset_parameters['provided']['builder']['certificate_type'] = testset.certificate_type
        testset_parameters['expected']['builder']['certificate_type'] = testset.certificate_type
        testset_parameters['expected']['outcome']['certificate_type'] = testset.certificate_type
        testset_parameters['provided']['builder']['subject'] = testset.certificate_subject
        testset_parameters['expected']['builder']['subject'] = testset.certificate_subject
        testset_parameters['expected']['outcome']['subject'] = testset.certificate_subject
        if tp_values == TestCertificateBuilder.TPValues.DEFINED:
            testset_parameters['provided']['builder']['term'] = testset.certificate_term
            testset_parameters['expected']['builder']['term'] = testset.certificate_term
            testset_parameters['expected']['outcome']['term'] = testset.certificate_term
            testset_parameters['provided']['builder']['alternative_names'] = testset.certificate_alternative_names
            testset_parameters['expected']['builder']['alternative_names'] = testset.certificate_alternative_names
            testset_parameters['expected']['outcome']['alternative_names'] = testset.certificate_alternative_names
            testset_parameters['provided']['builder']['extra_extensions'] = testset.certificate_extra_extensions
            testset_parameters['expected']['builder']['extra_extensions'] = testset.certificate_extra_extensions
            testset_parameters['expected']['outcome']['extra_extensions'] = testset.certificate_extra_extensions

        elif tp_values == TestCertificateBuilder.TPValues.DEFAULT:
            testset_parameters['expected']['builder']['term'] = None
            testset_parameters['expected']['outcome']['term'] = Constants.DEFAULT_CERTIFICATE_TERM
            testset_parameters['expected']['builder']['alternative_names'] = None
            testset_parameters['expected']['outcome']['alternative_names'] = []
            testset_parameters['expected']['builder']['extra_extensions'] = None
            testset_parameters['expected']['outcome']['extra_extensions'] = []
        else:
            raise ValueError(f'Unexpected tp_values value: {tp_values}')
        if tp_request == TestCertificateBuilder.TPRequest.CSR:
            testset_parameters['provided']['builder']['certificate_signing_request'] = testset.certificate_signing_request
            testset_parameters['expected']['builder']['certificate_signing_request'] = testset.certificate_signing_request
        elif tp_request == TestCertificateBuilder.TPRequest.INSTANT:
            testset_parameters['provided']['builder']['subject'] = testset.certificate_subject
            testset_parameters['provided']['builder']['alternative_names'] = testset.certificate_alternative_names
            testset_parameters['provided']['builder']['extra_extensions'] = testset.certificate_extra_extensions
            testset_parameters['expected']['builder']['certificate_signing_request'] = None
        else:
            raise ValueError(f'Unexpected tp_request value: {tp_request}')
        if tp_issuer == TestCertificateBuilder.TPIssuer.SELF:
            testset_parameters['expected']['builder']['issuer_private_key'] = None
            testset_parameters['expected']['outcome']['issuer_private_key'] = testset.private_key
            testset_parameters['expected']['builder']['issuer_subject'] = None
            testset_parameters['expected']['outcome']['issuer_subject'] = testset.certificate_subject
        elif tp_issuer == TestCertificateBuilder.TPIssuer.CA_ROOT:
            testset_parameters['provided']['builder']['issuer_private_key'] = testset_ca_root.private_key
            testset_parameters['expected']['builder']['issuer_private_key'] = testset_ca_root.private_key
            testset_parameters['expected']['outcome']['issuer_private_key'] = testset_ca_root.private_key
            testset_parameters['provided']['builder']['issuer_subject'] = testset_ca_root.certificate_subject
            testset_parameters['expected']['builder']['issuer_subject'] = testset_ca_root.certificate_subject
            testset_parameters['expected']['outcome']['issuer_subject'] = testset_ca_root.certificate_subject
        elif tp_issuer == TestCertificateBuilder.TPIssuer.CA_INTERMEDIATE_1:
            testset_parameters['provided']['builder']['issuer_private_key'] = testset_ca_intermediate_1.private_key
            testset_parameters['expected']['builder']['issuer_private_key'] = testset_ca_intermediate_1.private_key
            testset_parameters['expected']['outcome']['issuer_private_key'] = testset_ca_intermediate_1.private_key
            testset_parameters['provided']['builder']['issuer_subject'] = testset_ca_intermediate_1.certificate_subject
            testset_parameters['expected']['builder']['issuer_subject'] = testset_ca_intermediate_1.certificate_subject
            testset_parameters['expected']['outcome']['issuer_subject'] = testset_ca_intermediate_1.certificate_subject
        elif tp_issuer == TestCertificateBuilder.TPIssuer.CA_INTERMEDIATE_2:
            testset_parameters['provided']['builder']['issuer_private_key'] = testset_ca_intermediate_2.private_key
            testset_parameters['expected']['builder']['issuer_private_key'] = testset_ca_intermediate_2.private_key
            testset_parameters['expected']['outcome']['issuer_private_key'] = testset_ca_intermediate_2.private_key
            testset_parameters['provided']['builder']['issuer_subject'] = testset_ca_intermediate_2.certificate_subject
            testset_parameters['expected']['builder']['issuer_subject'] = testset_ca_intermediate_2.certificate_subject
            testset_parameters['expected']['outcome']['issuer_subject'] = testset_ca_intermediate_2.certificate_subject
        else:
            raise ValueError(f'Unexpected tp_issuer value: {tp_issuer}')

        logging.debug(
            '%s: %s; %s; %s; %s.',
            name,
            tp_configuring.value,
            tp_values.value,
            tp_request.value,
            tp_issuer.value,
        )
        logging.debug('Parameters provided to the testset: %s', testset_parameters['provided']['testset'])
        logging.debug('Parameters provided to the builder: %s', testset_parameters['provided']['builder'])
        logging.debug('Parameters expected from the builder: %s', testset_parameters['expected']['builder'])
        logging.debug('Parameters expected from the outcome: %s', testset_parameters['expected']['outcome'])

        certificate = None

        for tp_init in list(TestCertificateBuilder.TPInit):

            if tp_configuring == TestCertificateBuilder.TPConfiguring.CONSTRUCTOR:
                certificate_builder = CertificateBuilder(**testset_parameters['provided']['builder'])
            elif tp_configuring == TestCertificateBuilder.TPConfiguring.RUNTIME:
                certificate_builder = CertificateBuilder()
                for parameter_name, parameter_value in testset_parameters['provided']['builder'].items():
                    setattr(certificate_builder, parameter_name, parameter_value)
            elif tp_configuring == TestCertificateBuilder.TPConfiguring.FINAL_CALL:
                certificate_builder = CertificateBuilder()
            else:
                raise ValueError(f'Unknown test parameter value ({tp_configuring})')

            if tp_configuring != TestCertificateBuilder.TPConfiguring.FINAL_CALL:
                self._test_builder(
                    _builder=certificate_builder,
                    nickname=testset_parameters['expected']['builder']['nickname'],
                    llo=(TT.NONE,),
                    file=testset_parameters['expected']['builder']['file'],
                    chain_file=(TT.NONE,),
                    term=testset_parameters['expected']['builder']['term'],
                    ca=(TT.NONE,),
                    certificate_type=testset_parameters['expected']['builder']['certificate_type'],
                    issuer_private_key=testset_parameters['expected']['builder']['issuer_private_key'],
                    issuer_subject=testset_parameters['expected']['builder']['issuer_subject'],
                    private_key=testset_parameters['expected']['builder']['private_key'],
                    subject=testset_parameters['expected']['builder']['subject'],
                    alternative_names=[testset_parameters['expected']['builder']['alternative_names']],
                    extra_extensions=[testset_parameters['expected']['builder']['extra_extensions']],
                    certificate_signing_request=testset_parameters['expected']['builder']['certificate_signing_request'],
                )
            else:
                self._test_builder(
                    _builder=certificate_builder,
                    nickname=(TT.NONE,),
                    llo=(TT.NONE,),
                    file=(TT.NONE,),
                    chain_file=(TT.NONE,),
                    term=Constants.DEFAULT_CERTIFICATE_TERM,
                    ca=(TT.NONE,),
                    certificate_type=Constants.DEFAULT_CERTIFICATE_TYPE,
                    issuer_private_key=(TT.NONE,),
                    issuer_subject=(TT.NONE,),
                    private_key=(TT.NONE,),
                    subject=(TT.NONE,),
                    alternative_names=(TT.NONE,),
                    extra_extensions=(TT.NONE,),
                    certificate_signing_request=(TT.NONE,),
                )

            if tp_init == TestCertificateBuilder.TPInit.NEW:
                if tp_request == TestCertificateBuilder.TPRequest.INSTANT:
                    if tp_configuring == TestCertificateBuilder.TPConfiguring.FINAL_CALL:
                        certificate = certificate_builder.sign_instantly(**testset_parameters['provided']['builder'])
                    else:
                        certificate = certificate_builder.sign_instantly()
                elif tp_request == TestCertificateBuilder.TPRequest.CSR:
                    if tp_configuring == TestCertificateBuilder.TPConfiguring.FINAL_CALL:
                        certificate = certificate_builder.sign_csr(**testset_parameters['provided']['builder'])
                    else:
                        certificate = certificate_builder.sign_csr()
                else:
                    raise ValueError(f'Unknown test parameter value ({tp_request})')
                self._test_certificate(
                    _certificate=certificate,
                    nickname=testset_parameters['expected']['outcome']['nickname'],
                    llo=(TT.LAMBDA, [
                        lambda x: x.public_key().public_numbers().n == testset_parameters['expected']['outcome']['private_key'].llo.public_key().public_numbers().n,
                        lambda x: x.public_key().public_numbers().e == testset_parameters['expected']['outcome']['private_key'].llo.public_key().public_numbers().e,
                        lambda x: x.subject == testset_parameters['expected']['outcome']['subject'],
                        lambda x: x.issuer == testset_parameters['expected']['outcome']['issuer_subject'],
                    ]),
                    file=testset_parameters['expected']['outcome']['file'],
                    chain_file=(TT.NONE,),
                    certificate_type=testset_parameters['expected']['outcome']['certificate_type'],
                    term=testset_parameters['expected']['outcome']['term'],
                    ca=(TT.NONE,),
                    issuer_private_key=testset_parameters['expected']['outcome']['issuer_private_key'],
                    issuer_subject=testset_parameters['expected']['outcome']['issuer_subject'],
                    private_key=testset_parameters['expected']['outcome']['private_key'],
                    subject=testset_parameters['expected']['outcome']['subject'],
                    alternative_names=[testset_parameters['expected']['outcome']['alternative_names']],
                    extra_extensions=[testset_parameters['expected']['outcome']['extra_extensions']],
                )
            elif tp_init == TestCertificateBuilder.TPInit.LOAD_LLO:
                certificate = certificate_builder.init_with_llo(
                    nickname=certificate.nickname,
                    file=certificate.file,
                    llo=certificate.llo
                )
            elif tp_init == TestCertificateBuilder.TPInit.LOAD_FILE:
                certificate = certificate_builder.init_with_file(
                    nickname=certificate.nickname,
                    file=certificate.file,
                )
                self._test_certificate(
                    _certificate=certificate,
                    nickname=testset_parameters['expected']['outcome']['nickname'],
                    llo=(TT.LAMBDA, [
                        lambda x: x.public_key().public_numbers().n == testset_parameters['expected']['outcome']['private_key'].llo.public_key().public_numbers().n,
                        lambda x: x.public_key().public_numbers().e == testset_parameters['expected']['outcome']['private_key'].llo.public_key().public_numbers().e,
                        lambda x: x.subject == testset_parameters['expected']['outcome']['subject'],
                        lambda x: x.issuer == testset_parameters['expected']['outcome']['issuer_subject'],
                    ]),
                    file=testset_parameters['expected']['outcome']['file'],
                    chain_file=(TT.NONE,),
                    certificate_type=testset_parameters['expected']['outcome']['certificate_type'],
                    term=testset_parameters['expected']['outcome']['term'],
                    ca=(TT.NONE,),
                    issuer_private_key=(TT.NONE,),
                    issuer_subject=(TT.NONE,),
                    private_key=testset_parameters['expected']['outcome']['private_key'],
                    subject=testset_parameters['expected']['outcome']['subject'],
                    alternative_names=[testset_parameters['expected']['outcome']['alternative_names']],
                    extra_extensions=[testset_parameters['expected']['outcome']['extra_extensions']],
                )
            else:
                raise ValueError(f'Unknown test parameter value ({tp_init})')


    #
    # Test parametrization
    #

    # Test parameters passed to the constructor

    # def test_parameters_passed_to_constructor(self):
    #     testset = self.testing_set
    #     # with self.assertWarns(RuntimeWarning):
    #     certificate_builder = CertificateBuilder(
    #         nickname=testset.nickname,
    #         file=testset.certificate_file_name,
    #         private_key=testset.private_key,
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=testset.term,
    #         certificate_signing_request=testset.certificate_signing_request,
    #     )
    #     self._test_builder(
    #         _builder=certificate_builder,
    #         nickname=testset.nickname,
    #         llo=(TT.NONE,),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=testset.term,
    #         ca=(TT.NONE,),
    #         issuer_private_key=(TT.NONE,),
    #         issuer_subject=(TT.NONE,),
    #         private_key=testset.private_key,
    #         subject=(TT.NONE,),
    #         alternative_names=(TT.NONE,),
    #         extra_extensions=(TT.NONE,),
    #         certificate_signing_request=testset.certificate_signing_request,
    #     )
    #     with self.assertWarnsRegex(
    #             expected_warning=RuntimeWarning,
    #             expected_regex=r'the certificate signing request supposes a different type'
    #     ):
    #         certificate = certificate_builder.sign_csr()
    #     self._test_certificate(
    #         _certificate=certificate,
    #         nickname=self.testing_set.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == testset.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=testset.term,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset.private_key,
    #         issuer_subject=testset.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[],
    #     )
    #
    # def test_parameters_passed_to_constructor_with_default_values(self):
    #     testset = self.testing_set
    #     certificate_builder = CertificateBuilder(
    #         nickname=testset.nickname,
    #         file=testset.certificate_file_name,
    #         private_key=testset.private_key,
    #         certificate_signing_request=testset.certificate_signing_request
    #     )
    #     self._test_builder(
    #         _builder=certificate_builder,
    #         nickname=testset.nickname,
    #         llo=(TT.NONE,),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=(TT.NONE,),
    #         issuer_subject=(TT.NONE,),
    #         private_key=testset.private_key,
    #         subject=(TT.NONE,),
    #         alternative_names=(TT.NONE,),
    #         extra_extensions=(TT.NONE,),
    #         certificate_signing_request=testset.certificate_signing_request
    #     )
    #     certificate = certificate_builder.sign_csr()
    #     self._test_certificate(
    #         _certificate=certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == testset.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset.private_key,
    #         issuer_subject=testset.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[]
    #     )
    #
    # def test_parameters_added_at_runtime(self):
    #     testset = self.testing_set
    #     certificate_builder = CertificateBuilder() \
    #         .add_nickname(testset.nickname) \
    #         .add_file(testset.certificate_file_name) \
    #         .add_private_key(testset.private_key) \
    #         .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
    #         .add_term(testset.term) \
    #         .add_certificate_signing_request(testset.certificate_signing_request)
    #     self._test_builder(
    #         _builder=certificate_builder,
    #         nickname=testset.nickname,
    #         llo=(TT.NONE,),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=testset.term,
    #         ca=(TT.NONE,),
    #         issuer_private_key=(TT.NONE,),
    #         issuer_subject=(TT.NONE,),
    #         private_key=testset.private_key,
    #         subject=(TT.NONE,),
    #         alternative_names=(TT.NONE,),
    #         extra_extensions=(TT.NONE,),
    #         certificate_signing_request=testset.certificate_signing_request,
    #     )
    #     with self.assertWarnsRegex(
    #             expected_warning=RuntimeWarning,
    #             expected_regex=r'the certificate signing request supposes a different type'
    #     ):
    #         certificate = certificate_builder.sign_csr()
    #     self._test_certificate(
    #         _certificate=certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == testset.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=testset.term,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset.private_key,
    #         issuer_subject=testset.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[]
    #     )
    #
    # def test_parameters_added_at_runtime_with_default_values(self):
    #     testset = self.testing_set
    #     certificate_builder = CertificateBuilder() \
    #         .add_nickname(testset.nickname) \
    #         .add_file(testset.certificate_file_name) \
    #         .add_private_key(testset.private_key) \
    #         .add_certificate_signing_request(testset.certificate_signing_request)
    #     self._test_builder(
    #         _builder=certificate_builder,
    #         nickname=testset.nickname,
    #         llo=(TT.NONE,),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=(TT.NONE,),
    #         issuer_subject=(TT.NONE,),
    #         private_key=testset.private_key,
    #         subject=(TT.NONE,),
    #         alternative_names=(TT.NONE,),
    #         extra_extensions=(TT.NONE,),
    #         certificate_signing_request=testset.certificate_signing_request,
    #     )
    #     certificate = certificate_builder.sign_csr()
    #     self._test_certificate(
    #         _certificate=certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == testset.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset.private_key,
    #         issuer_subject=testset.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[]
    #     )
    #
    # def test_parameters_passed_with_final_call(self):
    #     testset = self.testing_set
    #     with self.assertWarnsRegex(
    #             expected_warning=RuntimeWarning,
    #             expected_regex=r'the certificate signing request supposes a different type'
    #     ):
    #         certificate = CertificateBuilder() \
    #             .sign_csr(
    #             nickname=testset.nickname,
    #             file=testset.certificate_file_name,
    #             private_key=testset.private_key,
    #             certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #             term=testset.term,
    #             certificate_signing_request=testset.certificate_signing_request
    #         )
    #     self._test_certificate(
    #         _certificate=certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == testset.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=testset.term,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset.private_key,
    #         issuer_subject=testset.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[]
    #     )
    #
    # def test_parameters_passed_with_final_call_with_default_values(self):
    #     testset = self.testing_set
    #     certificate = CertificateBuilder() \
    #         .sign_csr(
    #         nickname=testset.nickname,
    #         file=testset.certificate_file_name,
    #         private_key=testset.private_key,
    #         certificate_signing_request=testset.certificate_signing_request
    #     )
    #     self._test_certificate(
    #         _certificate=certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == testset.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset.private_key,
    #         issuer_subject=testset.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[]
    #     )
    #
    # def test_sign_csr(self):
    #     testset = self.testing_set
    #     with self.assertWarnsRegex(
    #             expected_warning=RuntimeWarning,
    #             expected_regex=r'the certificate signing request supposes a different type'
    #     ):
    #         certificate = CertificateBuilder() \
    #             .add_nickname(testset.nickname) \
    #             .add_file(testset.certificate_file_name) \
    #             .add_private_key(testset.private_key) \
    #             .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
    #             .add_subject(testset.subject) \
    #             .add_alternative_names(testset.alternativeNames) \
    #             .add_term(testset.term) \
    #             .add_certificate_signing_request(testset.certificate_signing_request) \
    #             .sign_csr()
    #     self._test_certificate(
    #         _certificate=certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == testset.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=testset.term,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset.private_key,
    #         issuer_subject=testset.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[],
    #     )
    #
    # def test_sign_csr_with_default_values(self):
    #     testset = self.testing_set
    #     certificate = CertificateBuilder() \
    #         .add_nickname(testset.nickname) \
    #         .add_file(testset.certificate_file_name) \
    #         .add_private_key(testset.private_key) \
    #         .add_certificate_signing_request(testset.certificate_signing_request) \
    #         .sign_csr()
    #     self._test_certificate(
    #         _certificate=certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == testset.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset.private_key,
    #         issuer_subject=testset.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[],
    #     )
    #
    # def test_sign_instantly(self):
    #     testset = self.testing_set
    #     certificate = CertificateBuilder() \
    #         .add_nickname(testset.nickname) \
    #         .add_file(testset.certificate_file_name) \
    #         .add_private_key(testset.private_key) \
    #         .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
    #         .add_subject(testset.subject) \
    #         .add_alternative_names(testset.alternativeNames) \
    #         .add_term(testset.term) \
    #         .sign_instantly()
    #     self._test_certificate(
    #         _certificate=certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == testset.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=testset.term,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset.private_key,
    #         issuer_subject=testset.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[]
    #     )
    #
    # def test_sign_instantly_with_default_values(self):
    #     testset = self.testing_set
    #     certificate = CertificateBuilder() \
    #         .add_nickname(testset.nickname) \
    #         .add_file(testset.certificate_file_name) \
    #         .add_private_key(testset.private_key) \
    #         .add_subject(testset.subject) \
    #         .sign_instantly()
    #     self._test_certificate(
    #         _certificate=certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == testset.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset.private_key,
    #         issuer_subject=testset.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[],
    #         extra_extensions=[]
    #     )
    #
    # def test_sign_csr_by_ca(self):
    #     testset_ca = TestingSet(
    #         subject=CertificateBuilder.compose_subject(
    #             country_name='PL',
    #             state_or_province_name='Malopolskie',
    #             locality_name='Krakow',
    #             organization_name='TUCHA SPOLKA Z OGRANICZONA ODPOWIEDZIALNOSCIA',
    #             organizational_unit_name='Security Service',
    #             email_address=f'security@{DOMAIN_NAME}',
    #             common_name='Root CA'
    #         )
    #     )
    #     certificate_ca = CertificateBuilder() \
    #         .add_nickname(testset_ca.nickname) \
    #         .add_file(testset_ca.certificate_file_name) \
    #         .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
    #         .add_private_key(testset_ca.private_key) \
    #         .add_subject(testset_ca.subject) \
    #         .sign_instantly()
    #     self._test_certificate(
    #         certificate_ca,
    #         nickname=testset_ca.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda
    #                 x: x.public_key().public_numbers().n == testset_ca.private_key.llo.public_key().public_numbers().n,
    #             lambda
    #                 x: x.public_key().public_numbers().e == testset_ca.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset_ca.subject,
    #             lambda x: x.issuer == testset_ca.subject,
    #         ]),
    #         file=testset_ca.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset_ca.private_key,
    #         issuer_subject=testset_ca.subject,
    #         private_key=testset_ca.private_key,
    #         subject=testset_ca.subject,
    #         alternative_names=[],
    #         extra_extensions=[]
    #     )
    #     testset = self.testing_set
    #     certificate = CertificateBuilder() \
    #         .add_nickname(testset.nickname) \
    #         .add_file(testset.certificate_file_name) \
    #         .add_chain_file(testset.certificate_chain_file_name) \
    #         .add_private_key(testset.private_key) \
    #         .add_certificate_signing_request(testset.certificate_signing_request) \
    #         .add_issuer_private_key(certificate_ca.private_key) \
    #         .add_issuer_subject(certificate_ca.subject) \
    #         .sign_csr()
    #     self._test_certificate(
    #         certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == certificate_ca.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=testset.certificate_chain_file_name,
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=testset.term,
    #         ca=(TT.NONE,),
    #         issuer_private_key=certificate_ca.private_key,
    #         issuer_subject=certificate_ca.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[]
    #     )
    #
    # def test_sign_instantly_by_ca(self):
    #     testset_ca = TestingSet(
    #         subject=CertificateBuilder.compose_subject(
    #             country_name='PL',
    #             state_or_province_name='Malopolskie',
    #             locality_name='Krakow',
    #             organization_name='TUCHA SPOLKA Z OGRANICZONA ODPOWIEDZIALNOSCIA',
    #             organizational_unit_name='Security Service',
    #             email_address=f'security@{DOMAIN_NAME}',
    #             common_name='Root CA'
    #         )
    #     )
    #     certificate_ca = CertificateBuilder() \
    #         .add_nickname(testset_ca.nickname) \
    #         .add_file(testset_ca.certificate_file_name) \
    #         .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
    #         .add_private_key(testset_ca.private_key) \
    #         .add_subject(testset_ca.subject) \
    #         .sign_instantly()
    #     self._test_certificate(
    #         certificate_ca,
    #         nickname=testset_ca.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda
    #                 x: x.public_key().public_numbers().n == testset_ca.private_key.llo.public_key().public_numbers().n,
    #             lambda
    #                 x: x.public_key().public_numbers().e == testset_ca.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset_ca.subject,
    #             lambda x: x.issuer == testset_ca.subject,
    #         ]),
    #         file=testset_ca.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=testset_ca.private_key,
    #         issuer_subject=testset_ca.subject,
    #         private_key=testset_ca.private_key,
    #         subject=testset_ca.subject,
    #         alternative_names=[],
    #         extra_extensions=[]
    #     )
    #     testset = self.testing_set
    #     certificate = CertificateBuilder() \
    #         .add_nickname(testset.nickname) \
    #         .add_file(testset.certificate_file_name) \
    #         .add_chain_file(testset.certificate_chain_file_name) \
    #         .add_private_key(testset.private_key) \
    #         .add_issuer_private_key(certificate_ca.private_key) \
    #         .add_issuer_subject(certificate_ca.subject) \
    #         .add_certificate_type(CertificateTypes.CLIENT) \
    #         .add_subject(testset.subject) \
    #         .add_alternative_names(testset.alternativeNames) \
    #         .add_term(testset.term) \
    #         .sign_instantly()
    #     self._test_certificate(
    #         certificate,
    #         nickname=testset.nickname,
    #         llo=(TT.LAMBDA, [
    #             lambda x: x.public_key().public_numbers().n == testset.private_key.llo.public_key().public_numbers().n,
    #             lambda x: x.public_key().public_numbers().e == testset.private_key.llo.public_key().public_numbers().e,
    #             lambda x: x.subject == testset.subject,
    #             lambda x: x.issuer == certificate_ca.subject,
    #         ]),
    #         file=testset.certificate_file_name,
    #         chain_file=testset.certificate_chain_file_name,
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=testset.term,
    #         ca=(TT.NONE,),
    #         issuer_private_key=certificate_ca.private_key,
    #         issuer_subject=certificate_ca.subject,
    #         private_key=testset.private_key,
    #         subject=testset.subject,
    #         alternative_names=[testset.alternativeNames],
    #         extra_extensions=[]
    #     )
    #
    # def test_reset(self, **kwargs):
    #     testset = self.testing_set
    #     certificate_builder = CertificateBuilder()
    #     self._test_builder(
    #         _builder=certificate_builder,
    #         nickname=(TT.NONE,),
    #         llo=(TT.NONE,),
    #         file=(TT.NONE,),
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=(TT.NONE,),
    #         issuer_subject=(TT.NONE,),
    #         private_key=(TT.NONE,),
    #         subject=(TT.NONE,),
    #         alternative_names=(TT.NONE,),
    #         extra_extensions=(TT.NONE,),
    #         certificate_signing_request=(TT.NONE,)
    #     )
    #     certificate_builder = CertificateBuilder() \
    #         .add_nickname(testset.nickname) \
    #         .add_file(testset.certificate_file_name) \
    #         .add_private_key(testset.private_key) \
    #         .add_certificate_type(CertificateTypes.CA_INTERMEDIATE) \
    #         .add_term(testset.term) \
    #         .add_certificate_signing_request(testset.certificate_signing_request)
    #     self._test_builder(
    #         _builder=certificate_builder,
    #         nickname=testset.nickname,
    #         llo=(TT.NONE,),
    #         file=testset.certificate_file_name,
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CA_INTERMEDIATE,
    #         term=testset.term,
    #         ca=(TT.NONE,),
    #         issuer_private_key=(TT.NONE,),
    #         issuer_subject=(TT.NONE,),
    #         private_key=testset.private_key,
    #         subject=(TT.NONE,),
    #         alternative_names=(TT.NONE,),
    #         extra_extensions=(TT.NONE,),
    #         certificate_signing_request=testset.certificate_signing_request
    #     )
    #     certificate_builder.reset()
    #     self._test_builder(
    #         _builder=certificate_builder,
    #         nickname=(TT.NONE,),
    #         llo=(TT.NONE,),
    #         file=(TT.NONE,),
    #         chain_file=(TT.NONE,),
    #         certificate_type=CertificateTypes.CLIENT,
    #         term=Constants.DEFAULT_CERTIFICATE_TERM,
    #         ca=(TT.NONE,),
    #         issuer_private_key=(TT.NONE,),
    #         issuer_subject=(TT.NONE,),
    #         private_key=(TT.NONE,),
    #         subject=(TT.NONE,),
    #         alternative_names=(TT.NONE,),
    #         extra_extensions=(TT.NONE,),
    #         certificate_signing_request=(TT.NONE,)
    #     )
