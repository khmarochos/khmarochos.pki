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

    class TPParametersPassing(Enum):
        CONSTRUCTOR = 'passing parameters to the constructor'
        RUNTIME = 'adding parameters at runtime'
        FINAL_CALL = 'passing parameters with the final call'

    class TPValuesAssignment(Enum):
        DEFAULT = 'using default values'
        DEFINED = 'using defined values'

    class TPSigningRequest(Enum):
        CSR = 'using a certificate signing request'
        INSTANT = 'instantly signing the certificate'

    class TPSigningKey(Enum):
        SELF = 'signing the certificate by itself'
        CA_ROOT = 'signing the certificate by a CA'
        CA_INTERMEDIATE_1 = 'signing the certificate by an intermediate CA signed by a root CA'
        CA_INTERMEDIATE_2 = 'signing the certificate by an intermediate CA signed by another intermediate CA'

    class TPInit(Enum):
        NEW = 'creating a new certificate'
        LOAD_LLO = 'load a certificate from x509.Certificate'
        LOAD_FILE = 'load a certificate from a file'

    PARAMETER_SETS = []
    for tp_parameters_passing in list(TPParametersPassing):
        for tp_values_assignment in list(TPValuesAssignment):
            for tp_signing_request in list(TPSigningRequest):
                for tp_signing_key in list(TPSigningKey):
                    PARAMETER_SETS.append((
                        '__'.join((
                            tp_parameters_passing.name,
                            tp_values_assignment.name,
                            tp_signing_request.name,
                            tp_signing_key.name
                        )),
                        tp_parameters_passing,
                        tp_values_assignment,
                        tp_signing_request,
                        tp_signing_key
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
                TestCertificateBuilder.TPSigningKey.CA_ROOT,
                TestCertificateBuilder.TPSigningKey.CA_INTERMEDIATE_1,
                TestCertificateBuilder.TPSigningKey.CA_INTERMEDIATE_2
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
                TestCertificateBuilder.TPSigningKey.CA_INTERMEDIATE_1,
                TestCertificateBuilder.TPSigningKey.CA_INTERMEDIATE_2
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
                TestCertificateBuilder.TPSigningKey.CA_INTERMEDIATE_2,
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
        provided_to_testset = testset_parameters['provided']['testset']
        provided_to_builder = testset_parameters['provided']['builder']
        expected_in_builder = testset_parameters['expected']['builder']
        expected_in_outcome = testset_parameters['expected']['outcome']

        provided_to_testset['nickname'] = randomizer
        provided_to_testset['passphrase_random'] = True
        provided_to_testset['passphrase_length'] = randomizer
        provided_to_testset['passphrase_character_set'] = randomizer
        provided_to_testset['certificate_type'] = CertificateTypes.CLIENT
        if tp_values == TestCertificateBuilder.TPValuesAssignment.DEFINED:
            provided_to_testset['certificate_term'] = randomizer
            provided_to_testset['certificate_subject_common_name'] = randomizer
            provided_to_testset['certificate_alternative_names'] = randomizer
            provided_to_testset['certificate_extra_extensions'] = []
        elif tp_values == TestCertificateBuilder.TPValuesAssignment.DEFAULT:
            pass
        else:
            raise ValueError(f'Unexpected tp_values value: {tp_values}')
        if tp_request == TestCertificateBuilder.TPSigningRequest.CSR:
            pass
        elif tp_request == TestCertificateBuilder.TPSigningRequest.INSTANT:
            pass
        if tp_issuer == TestCertificateBuilder.TPSigningKey.SELF:
            pass
        elif tp_issuer == TestCertificateBuilder.TPSigningKey.CA_ROOT:
            provided_to_testset['certificate_issuer_private_key'] = testset_ca_root.private_key
            provided_to_testset['certificate_issuer_subject'] = testset_ca_root.certificate_subject
        elif tp_issuer == TestCertificateBuilder.TPSigningKey.CA_INTERMEDIATE_1:
            provided_to_testset['certificate_issuer_private_key'] = testset_ca_intermediate_1.private_key
            provided_to_testset['certificate_issuer_subject'] = testset_ca_intermediate_1.certificate_subject
        elif tp_issuer == TestCertificateBuilder.TPSigningKey.CA_INTERMEDIATE_2:
            provided_to_testset['certificate_issuer_private_key'] = testset_ca_intermediate_2.private_key
            provided_to_testset['certificate_issuer_subject'] = testset_ca_intermediate_2.certificate_subject
        else:
            raise ValueError(f'Unexpected tp_issuer value: {tp_issuer}')

        testset = TestingSet(**provided_to_testset)

        provided_to_builder['nickname'] = testset.nickname
        expected_in_builder['nickname'] = testset.nickname
        expected_in_outcome['nickname'] = testset.nickname
        provided_to_builder['file'] = testset.certificate_file_name
        expected_in_builder['file'] = testset.certificate_file_name
        expected_in_outcome['file'] = testset.certificate_file_name
        provided_to_builder['private_key'] = testset.private_key
        expected_in_builder['private_key'] = testset.private_key
        expected_in_outcome['private_key'] = testset.private_key
        provided_to_builder['certificate_type'] = testset.certificate_type
        expected_in_builder['certificate_type'] = testset.certificate_type
        expected_in_outcome['certificate_type'] = testset.certificate_type
        provided_to_builder['subject'] = testset.certificate_subject
        expected_in_builder['subject'] = testset.certificate_subject
        expected_in_outcome['subject'] = testset.certificate_subject
        if tp_values == TestCertificateBuilder.TPValuesAssignment.DEFINED:
            provided_to_builder['term'] = testset.certificate_term
            expected_in_builder['term'] = testset.certificate_term
            expected_in_outcome['term'] = testset.certificate_term
            provided_to_builder['alternative_names'] = testset.certificate_alternative_names
            expected_in_builder['alternative_names'] = testset.certificate_alternative_names
            expected_in_outcome['alternative_names'] = testset.certificate_alternative_names
            provided_to_builder['extra_extensions'] = testset.certificate_extra_extensions
            expected_in_builder['extra_extensions'] = testset.certificate_extra_extensions
            expected_in_outcome['extra_extensions'] = testset.certificate_extra_extensions
        elif tp_values == TestCertificateBuilder.TPValuesAssignment.DEFAULT:
            expected_in_builder['term'] = None
            expected_in_outcome['term'] = Constants.DEFAULT_CERTIFICATE_TERM
            expected_in_builder['alternative_names'] = None
            expected_in_outcome['alternative_names'] = []
            expected_in_builder['extra_extensions'] = None
            expected_in_outcome['extra_extensions'] = []
        else:
            raise ValueError(f'Unexpected tp_values value: {tp_values}')
        if tp_request == TestCertificateBuilder.TPSigningRequest.CSR:
            provided_to_builder['certificate_signing_request'] = testset.certificate_signing_request
            expected_in_builder['certificate_signing_request'] = testset.certificate_signing_request
        elif tp_request == TestCertificateBuilder.TPSigningRequest.INSTANT:
            provided_to_builder['subject'] = testset.certificate_subject
            provided_to_builder['alternative_names'] = testset.certificate_alternative_names
            provided_to_builder['extra_extensions'] = testset.certificate_extra_extensions
            expected_in_builder['certificate_signing_request'] = None
        else:
            raise ValueError(f'Unexpected tp_request value: {tp_request}')
        if tp_issuer == TestCertificateBuilder.TPSigningKey.SELF:
            expected_in_builder['issuer_private_key'] = None
            expected_in_outcome['issuer_private_key'] = testset.private_key
            expected_in_builder['issuer_subject'] = None
            expected_in_outcome['issuer_subject'] = testset.certificate_subject
        elif tp_issuer == TestCertificateBuilder.TPSigningKey.CA_ROOT:
            provided_to_builder['issuer_private_key'] = testset_ca_root.private_key
            expected_in_builder['issuer_private_key'] = testset_ca_root.private_key
            expected_in_outcome['issuer_private_key'] = testset_ca_root.private_key
            provided_to_builder['issuer_subject'] = testset_ca_root.certificate_subject
            expected_in_builder['issuer_subject'] = testset_ca_root.certificate_subject
            expected_in_outcome['issuer_subject'] = testset_ca_root.certificate_subject
        elif tp_issuer == TestCertificateBuilder.TPSigningKey.CA_INTERMEDIATE_1:
            provided_to_builder['issuer_private_key'] = testset_ca_intermediate_1.private_key
            expected_in_builder['issuer_private_key'] = testset_ca_intermediate_1.private_key
            expected_in_outcome['issuer_private_key'] = testset_ca_intermediate_1.private_key
            provided_to_builder['issuer_subject'] = testset_ca_intermediate_1.certificate_subject
            expected_in_builder['issuer_subject'] = testset_ca_intermediate_1.certificate_subject
            expected_in_outcome['issuer_subject'] = testset_ca_intermediate_1.certificate_subject
        elif tp_issuer == TestCertificateBuilder.TPSigningKey.CA_INTERMEDIATE_2:
            provided_to_builder['issuer_private_key'] = testset_ca_intermediate_2.private_key
            expected_in_builder['issuer_private_key'] = testset_ca_intermediate_2.private_key
            expected_in_outcome['issuer_private_key'] = testset_ca_intermediate_2.private_key
            provided_to_builder['issuer_subject'] = testset_ca_intermediate_2.certificate_subject
            expected_in_builder['issuer_subject'] = testset_ca_intermediate_2.certificate_subject
            expected_in_outcome['issuer_subject'] = testset_ca_intermediate_2.certificate_subject
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
        logging.debug('Parameters provided to the testset: %s', provided_to_testset)
        logging.debug('Parameters provided to the builder: %s', provided_to_builder)
        logging.debug('Parameters expected from the builder: %s', expected_in_builder)
        logging.debug('Parameters expected from the outcome: %s', expected_in_outcome)

        certificate = None

        for tp_init in list(TestCertificateBuilder.TPInit):

            if tp_configuring == TestCertificateBuilder.TPParametersPassing.CONSTRUCTOR:
                certificate_builder = CertificateBuilder(**provided_to_builder)
            elif tp_configuring == TestCertificateBuilder.TPParametersPassing.RUNTIME:
                certificate_builder = CertificateBuilder()
                for parameter_name, parameter_value in provided_to_builder.items():
                    setattr(certificate_builder, parameter_name, parameter_value)
            elif tp_configuring == TestCertificateBuilder.TPParametersPassing.FINAL_CALL:
                certificate_builder = CertificateBuilder()
            else:
                raise ValueError(f'Unknown test parameter value ({tp_configuring})')

            if tp_configuring != TestCertificateBuilder.TPParametersPassing.FINAL_CALL:
                self._test_builder(
                    _builder=certificate_builder,
                    nickname=expected_in_builder['nickname'],
                    llo=(TT.NONE,),
                    file=expected_in_builder['file'],
                    chain_file=(TT.NONE,),
                    term=expected_in_builder['term'],
                    ca=(TT.NONE,),
                    certificate_type=expected_in_builder['certificate_type'],
                    issuer_private_key=expected_in_builder['issuer_private_key'],
                    issuer_subject=expected_in_builder['issuer_subject'],
                    private_key=expected_in_builder['private_key'],
                    subject=expected_in_builder['subject'],
                    alternative_names=[expected_in_builder['alternative_names']],
                    extra_extensions=[expected_in_builder['extra_extensions']],
                    certificate_signing_request=expected_in_builder['certificate_signing_request'],
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
                if tp_request == TestCertificateBuilder.TPSigningRequest.INSTANT:
                    certificate = certificate_builder.sign_instantly(**(
                        provided_to_builder
                        if tp_configuring == TestCertificateBuilder.TPParametersPassing.FINAL_CALL
                        else {}
                    ))
                elif tp_request == TestCertificateBuilder.TPSigningRequest.CSR:
                    certificate = certificate_builder.sign_csr(**(
                        provided_to_builder
                        if tp_configuring == TestCertificateBuilder.TPParametersPassing.FINAL_CALL
                        else {})
                   )
                else:
                    raise ValueError(f'Unknown test parameter value ({tp_request})')
            elif tp_init == TestCertificateBuilder.TPInit.LOAD_LLO:
                certificate = CertificateBuilder().init_with_llo(
                    nickname=certificate.nickname,
                    private_key=certificate.private_key,
                    file=certificate.file,
                    llo=certificate.llo
                )
            elif tp_init == TestCertificateBuilder.TPInit.LOAD_FILE:
                certificate = CertificateBuilder().init_with_file(
                    nickname=certificate.nickname,
                    private_key=certificate.private_key,
                    file=certificate.file,
                )
            else:
                raise ValueError(f'Unknown test parameter value ({tp_init})')

            self._test_certificate(
                _certificate=certificate,
                nickname=expected_in_outcome['nickname'],
                llo=(TT.LAMBDA, [
                    lambda x: x.public_key().public_numbers().n == expected_in_outcome['private_key'].llo.public_key().public_numbers().n,
                    lambda x: x.public_key().public_numbers().e == expected_in_outcome['private_key'].llo.public_key().public_numbers().e,
                    lambda x: x.subject == expected_in_outcome['subject'],
                    lambda x: x.issuer == expected_in_outcome['issuer_subject'],
                ]),
                file=expected_in_outcome['file'],
                chain_file=(TT.NONE,),
                certificate_type=expected_in_outcome['certificate_type'],
                term=expected_in_outcome['term'],
                ca=(TT.NONE,),
                issuer_private_key=
                    expected_in_outcome['issuer_private_key']
                    if tp_init == TestCertificateBuilder.TPInit.NEW
                    else (TT.NONE,),
                issuer_subject=
                    expected_in_outcome['issuer_subject']
                    if tp_init == TestCertificateBuilder.TPInit.NEW
                    else (TT.NONE,),
                private_key=expected_in_outcome['private_key'],
                subject=expected_in_outcome['subject'],
                alternative_names=[expected_in_outcome['alternative_names']],
                extra_extensions=[expected_in_outcome['extra_extensions']],
            )

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
