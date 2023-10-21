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
from enum import Enum

import cryptography.x509
from cryptography import x509
from cryptography.hazmat.primitives._serialization import Encoding
from parameterized import parameterized

from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import \
    CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request_builder import \
    CertificateSigningRequestBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes, Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase_builder import PassphraseBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key_builder import PrivateKeyBuilder
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderTestType as TT, \
    StopAfter, TestingSet, Randomizer
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import BuilderCheckList
from ansible_collections.khmarochos.pki.tests.unit.modules.abstract_builder_test_set import AbstractBuilderTest


# noinspection DuplicatedCode
class TestCertificateSigningRequestBuilder(unittest.TestCase, AbstractBuilderTest):

    class TPParametersPassing(Enum):
        CONSTRUCTOR = 'passing parameters to the constructor'
        RUNTIME = 'adding parameters at runtime'
        FINAL_CALL = 'passing parameters with the final call'

    class TPValuesAssignment(Enum):
        DEFAULT = 'using default values'
        DEFINED = 'using defined values'

    class TPInit(Enum):
        NEW = 'creating a new certificate signing request'
        LOAD_LLO = 'load a certificate signing request from x509.CertificateSigningRequest'
        LOAD_FILE = 'load a certificate signing request from a file'

    PARAMETER_SETS = []
    for tp_parameters_passing in list(TPParametersPassing):
        for tp_values_assignment in list(TPValuesAssignment):
            for tp_init in list(TPInit):
                PARAMETER_SETS.append((
                    '__'.join((
                        tp_parameters_passing.name,
                        tp_values_assignment.name,
                        tp_init.name,
                    )),
                    tp_parameters_passing,
                    tp_values_assignment,
                    tp_init,
                ))

    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig(level=logging.INFO, handlers=[logging.StreamHandler(sys.stdout)])

    def _test_builder(
            self,
            _builder: BuilderCheckList[CertificateSigningRequestBuilder],
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
            _object_to_test=_builder,
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
            _certificate_signing_request: CertificateSigningRequest,
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
            _object_to_test=_certificate_signing_request,
            nickname=nickname,
            llo=llo,
            file=file,
            certificate_type=certificate_type,
            private_key=private_key,
            subject=subject,
            alternative_names=alternative_names,
            extra_extensions=extra_extensions
        )

    @parameterized.expand(PARAMETER_SETS)
    def test_everything(self, name, tp_parameters_passing, tp_values_assignment, tp_init):

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
        provided_to_testset['passphrase_length'] = randomizer
        provided_to_testset['passphrase_character_set'] = randomizer
        provided_to_testset['certificate_type'] = CertificateTypes.CLIENT
        if tp_values_assignment == TestCertificateSigningRequestBuilder.TPValuesAssignment.DEFINED:
            provided_to_testset['certificate_subject_common_name'] = randomizer
            provided_to_testset['certificate_alternative_names'] = randomizer
            provided_to_testset['certificate_extra_extensions'] = []
        elif tp_values_assignment == TestCertificateSigningRequestBuilder.TPValuesAssignment.DEFAULT:
            pass
        else:
            raise ValueError(f'Unexpected tp_values value: {tp_values_assignment}')

        testset = TestingSet(stop_after=StopAfter.CERTIFICATE_SIGNING_REQUEST, **provided_to_testset)

        provided_to_builder['nickname'] = testset.nickname
        expected_in_builder['nickname'] = testset.nickname
        expected_in_outcome['nickname'] = testset.nickname
        provided_to_builder['file'] = testset.certificate_signing_request_file_name
        expected_in_builder['file'] = testset.certificate_signing_request_file_name
        expected_in_outcome['file'] = testset.certificate_signing_request_file_name
        provided_to_builder['private_key'] = testset.private_key
        expected_in_builder['private_key'] = testset.private_key
        expected_in_outcome['private_key'] = testset.private_key
        provided_to_builder['certificate_type'] = testset.certificate_type
        expected_in_builder['certificate_type'] = testset.certificate_type
        expected_in_outcome['certificate_type'] = testset.certificate_type
        provided_to_builder['subject'] = testset.certificate_subject
        expected_in_builder['subject'] = testset.certificate_subject
        expected_in_outcome['subject'] = testset.certificate_subject
        if tp_values_assignment == TestCertificateSigningRequestBuilder.TPValuesAssignment.DEFINED:
            provided_to_builder['alternative_names'] = testset.certificate_alternative_names
            expected_in_builder['alternative_names'] = testset.certificate_alternative_names
            expected_in_outcome['alternative_names'] = testset.certificate_alternative_names
            provided_to_builder['extra_extensions'] = testset.certificate_extra_extensions
            expected_in_builder['extra_extensions'] = testset.certificate_extra_extensions
            expected_in_outcome['extra_extensions'] = testset.certificate_extra_extensions
        elif tp_values_assignment == TestCertificateSigningRequestBuilder.TPValuesAssignment.DEFAULT:
            expected_in_builder['alternative_names'] = None
            expected_in_outcome['alternative_names'] = []
            expected_in_builder['extra_extensions'] = None
            expected_in_outcome['extra_extensions'] = []
        else:
            raise ValueError(f'Unexpected tp_values value: {tp_values_assignment}')

        logging.debug(
            '%s: %s; %s; %s.',
            name,
            tp_parameters_passing.value,
            tp_values_assignment.value,
            tp_init.value
        )
        logging.debug('Parameters provided to the testset: %s', provided_to_testset)
        logging.debug('Parameters provided to the builder: %s', provided_to_builder)
        logging.debug('Parameters expected from the builder: %s', expected_in_builder)
        logging.debug('Parameters expected from the outcome: %s', expected_in_outcome)

        certificate_signing_request = None

        for tp_init in list(TestCertificateSigningRequestBuilder.TPInit):

            if tp_parameters_passing == TestCertificateSigningRequestBuilder.TPParametersPassing.CONSTRUCTOR:
                certificate_signing_request_builder = CertificateSigningRequestBuilder(**provided_to_builder)
            elif tp_parameters_passing == TestCertificateSigningRequestBuilder.TPParametersPassing.RUNTIME:
                certificate_signing_request_builder = CertificateSigningRequestBuilder()
                for parameter_name, parameter_value in provided_to_builder.items():
                    setattr(certificate_signing_request_builder, parameter_name, parameter_value)
            elif tp_parameters_passing == TestCertificateSigningRequestBuilder.TPParametersPassing.FINAL_CALL:
                certificate_signing_request_builder = CertificateSigningRequestBuilder()
            else:
                raise ValueError(f'Unknown test parameter value ({tp_parameters_passing})')

            if tp_parameters_passing != TestCertificateSigningRequestBuilder.TPParametersPassing.FINAL_CALL:
                self._test_builder(
                    _builder=certificate_signing_request_builder,
                    nickname=expected_in_builder['nickname'],
                    llo=(TT.NONE,),
                    file=expected_in_builder['file'],
                    certificate_type=expected_in_builder['certificate_type'],
                    private_key=expected_in_builder['private_key'],
                    subject=expected_in_builder['subject'],
                    alternative_names=[expected_in_builder['alternative_names']],
                    extra_extensions=[expected_in_builder['extra_extensions']],
                )
            else:
                self._test_builder(
                    _builder=certificate_signing_request_builder,
                    nickname=(TT.NONE,),
                    llo=(TT.NONE,),
                    file=(TT.NONE,),
                    certificate_type=Constants.DEFAULT_CERTIFICATE_TYPE,
                    private_key=(TT.NONE,),
                    subject=(TT.NONE,),
                    alternative_names=(TT.NONE,),
                    extra_extensions=(TT.NONE,),
                )

            if tp_init == TestCertificateSigningRequestBuilder.TPInit.NEW:
                certificate_signing_request = certificate_signing_request_builder.init_new(**(
                    provided_to_builder
                    if tp_parameters_passing == TestCertificateSigningRequestBuilder.TPParametersPassing.FINAL_CALL
                    else {}
                ))
            elif tp_init == TestCertificateSigningRequestBuilder.TPInit.LOAD_LLO:
                certificate_signing_request = CertificateSigningRequestBuilder().init_with_llo(
                    nickname=certificate_signing_request.nickname,
                    private_key=certificate_signing_request.private_key,
                    file=certificate_signing_request.file,
                    llo=certificate_signing_request.llo
                )
            elif tp_init == TestCertificateSigningRequestBuilder.TPInit.LOAD_FILE:
                certificate_signing_request = CertificateSigningRequestBuilder().init_with_file(
                    nickname=certificate_signing_request.nickname,
                    private_key=certificate_signing_request.private_key,
                    file=certificate_signing_request.file,
                )
            else:
                raise ValueError(f'Unknown test parameter value ({tp_init})')

            self._test_certificate_signing_request(
                _certificate_signing_request=certificate_signing_request,
                nickname=expected_in_outcome['nickname'],
                llo=(TT.LAMBDA, [
                    lambda x: x.public_key().public_numbers().n == expected_in_outcome['private_key'].llo.public_key().public_numbers().n,
                    lambda x: x.public_key().public_numbers().e == expected_in_outcome['private_key'].llo.public_key().public_numbers().e,
                    lambda x: x.subject == expected_in_outcome['subject'],
                ]),
                file=expected_in_outcome['file'],
                certificate_type=expected_in_outcome['certificate_type'],
                private_key=expected_in_outcome['private_key'],
                subject=expected_in_outcome['subject'],
                alternative_names=[expected_in_outcome['alternative_names']],
                extra_extensions=[expected_in_outcome['extra_extensions']],
            )

            logging.debug('Certificate signing request: %s', certificate_signing_request)
