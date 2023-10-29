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
import warnings
from typing import Union

from cryptography import x509

from ansible_collections.khmarochos.pki.plugins.module_utils.certificate import Certificate
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import \
    CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.pki_ca import PKICA
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes, Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_builder_base import CertificateBuilderBase
from ansible_collections.khmarochos.pki.plugins.module_utils.flexibuilder import FlexiBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class CertificateBuilder(CertificateBuilderBase, FlexiBuilder, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'type': str,
        'mandatory': False,
        'default': None,
        'readonly': False,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
        'add_builder_updater': True
    },
    'nickname': {},
    'llo': {'type': x509.Certificate},
    'file': {},
    'chain_file': {},
    'certificate_type': {'type': CertificateTypes, 'default': Constants.DEFAULT_CERTIFICATE_TYPE},
    'term': {'type': int, 'default': Constants.DEFAULT_CERTIFICATE_TERM},
    'ca': {'type': PKICA},
    'issuer_private_key': {'type': PrivateKey},
    'issuer_subject': {'type': x509.name.Name},
    'private_key': {'type': PrivateKey},
    'subject': {'type': x509.name.Name},
    'alternative_names': {'type': list},
    'extra_extensions': {'type': list},
    'certificate_signing_request': {'type': CertificateSigningRequest},
}):

    @FlexiBuilder.parameters_assigner
    def _assign_parameters(
            self,
            parameters_to_assign: dict = None,
            parameters_to_merge: dict = None,
            parameters_assigned: dict = None
    ) -> dict:
        if (certificate_signing_request := parameters_assigned.get('certificate_signing_request')) is not None:
            if parameters_assigned.get('certificate_type') is None:
                parameters_assigned['certificate_type'] = certificate_signing_request.certificate_type
            if parameters_assigned.get('private_key') is None:
                parameters_assigned['private_key'] = certificate_signing_request.private_key
            if parameters_assigned.get('subject') is None:
                parameters_assigned['subject'] = certificate_signing_request.subject
            if parameters_assigned.get('alternative_names') is None:
                parameters_assigned['alternative_names'] = certificate_signing_request.alternative_names
            if parameters_assigned.get('extra_extensions') is None:
                parameters_assigned['extra_extensions'] = certificate_signing_request.extra_extensions
        if (ca := parameters_assigned.get('ca')) is not None:
            ca_private_key = ca.certificate.private_key
            ca_issuer_subject = ca.certificate.subject
        else:
            ca_private_key = None
            ca_issuer_subject = None
        if 'issuer_private_key' in parameters_to_assign:
            if parameters_assigned.get('issuer_private_key') is None:
                parameters_assigned['issuer_private_key'] = \
                    ca_private_key \
                        if ca_private_key is not None \
                        else parameters_assigned.get('private_key')
            elif ca is not None and parameters_assigned.get('issuer_private_key') != ca_private_key:
                raise ValueError(f"The issuer_private_key parameter is given as "
                                 f"{parameters_assigned.get('issuer_private_key')} but "
                                 f"the CA has a different private key which is {ca_private_key}")
        if 'issuer_subject' in parameters_to_assign:
            if parameters_assigned.get('issuer_subject') is None:
                parameters_assigned['issuer_subject'] = \
                    ca_issuer_subject \
                        if ca_issuer_subject is not None \
                        else parameters_assigned.get('subject')
            elif ca is not None and parameters_assigned.get('issuer_subject') != ca_issuer_subject:
                raise ValueError(f"The issuer_subject parameter is given as "
                                 f"{parameters_assigned.get('issuer_subject')} but "
                                 f"the CA has a different subject which is {ca_issuer_subject}")
        if 'alternative_names' in parameters_to_assign and parameters_assigned.get('alternative_names') is None:
            parameters_assigned['alternative_names'] = []
        if 'extra_extensions' in parameters_to_assign and parameters_assigned.get('extra_extensions') is None:
            parameters_assigned['extra_extensions'] = []
        return parameters_assigned

    @staticmethod
    def _check_after_load(
            certificate: Certificate,
            parameters_assigned: dict,
            raise_exception: bool = True
    ) -> bool:
        result = FlexiBuilder.check_after_load_universal(
            object_to_check=certificate,
            parameters_assigned=parameters_assigned,
            parameters_to_check=['chain_file', 'certificate_type', 'term', 'ca', 'private_key', 'subject',
                                 'alternative_names', 'extra_extensions'],
            raise_exception=raise_exception
        )
        return result

    def init_with_file(
            self,
            nickname: str = None,
            file: str = None,
            private_key: PrivateKey = None,
    ) -> Certificate:
        parameters_assigned = self._assign_parameters({
            'nickname': {'mandatory': True},
            'file': {'mandatory': True},
            'private_key': {'mandatory': True},
        })
        certificate = Certificate(**parameters_assigned)
        certificate.load()
        CertificateBuilder._check_after_load(certificate, parameters_assigned)
        return certificate

    def init_with_llo(
            self,
            nickname: str = None,
            file: str = None,
            llo: x509.Certificate = None,
            private_key: PrivateKey = None,
            save: bool = True,
            save_chain: bool = True
    ):
        parameters_assigned = self._assign_parameters({
            'nickname': {'mandatory': True},
            'file': {'mandatory': True},
            'llo': {'mandatory': True},
            'private_key': {'mandatory': True},
        })
        certificate = Certificate(**parameters_assigned)
        certificate.anatomize_llo()
        CertificateBuilder._check_after_load(certificate, parameters_assigned)
        if save:
            certificate.save()
        if save_chain:
            certificate.save_chain()
        return certificate

    def sign_instantly(
            self,
            nickname: str = None,
            file: str = None,
            chain_file: str = None,
            certificate_type: CertificateTypes = None,
            term: int = None,
            ca: PKICA = None,
            issuer_private_key: PrivateKey = None,
            issuer_subject: x509.name.Name = None,
            private_key: PrivateKey = None,
            subject: x509.name.Name = None,
            alternative_names: list = None,
            extra_extensions: list = None,
            save: bool = True,
            save_chain: bool = True
    ) -> Certificate:
        parameters_assigned = self._assign_parameters({
            'nickname': {'mandatory': True},
            'file': {'mandatory': True},
            'chain_file': {},
            'certificate_type': {},
            'term': {},
            'ca': {},
            'issuer_private_key': {},
            'issuer_subject': {},
            'private_key': {'mandatory': True},
            'subject': {'mandatory': True},
            'alternative_names': {},
            'extra_extensions': {},
        })
        certificate = Certificate(
            **parameters_assigned,
            llo=self.build_llo(
                builder=x509.CertificateBuilder(),
                issuer_private_key=parameters_assigned.get('issuer_private_key'),
                issuer_subject=parameters_assigned.get('issuer_subject'),
                private_key=parameters_assigned.get('private_key'),
                certificate_type=parameters_assigned.get('certificate_type'),
                term=parameters_assigned.get('term'),
                subject=parameters_assigned.get('subject'),
                alternative_names=parameters_assigned.get('alternative_names'),
                extra_extensions=parameters_assigned.get('extra_extensions')
        ))
        certificate.anatomize_llo()
        certificate.save()
        certificate.save_chain()
        return certificate

    def sign_csr(
            self,
            nickname: str = None,
            file: str = None,
            chain_file: str = None,
            certificate_type: CertificateTypes = None,
            term: int = None,
            ca: PKICA = None,
            issuer_private_key: PrivateKey = None,
            issuer_subject: x509.name.Name = None,
            private_key: PrivateKey = None,
            subject: x509.name.Name = None,
            alternative_names: list = None,
            extra_extensions: list = None,
            certificate_signing_request: CertificateSigningRequest = None,
    ) -> Certificate:
        parameters_assigned = self._assign_parameters({
            'nickname': {'mandatory': True},
            'file': {'mandatory': True},
            'chain_file': {},
            'certificate_type': {},
            'term': {},
            'ca': {},
            'issuer_private_key': {},
            'issuer_subject': {},
            'private_key': {},
            'subject': {},
            'alternative_names': {},
            'extra_extensions': {},
            'certificate_signing_request': {'mandatory': True},
        })
        logging.debug(f"ASSIGNED: {parameters_assigned}")
        # # Perform some sanity checks
        # if private_key not in (None, certificate_signing_request.private_key):
        #     warnings.warn(f'The private_key parameter is given as {private_key} '
        #                   f'but the certificate signing request supposes a different private key which is '
        #                   f'{certificate_signing_request.private_key}', RuntimeWarning)
        # if certificate_type not in (None, certificate_signing_request.certificate_type):
        #     warnings.warn(f'The certificate_type parameter is given as {certificate_type} '
        #                   'but the certificate signing request supposes a different type which is '
        #                   f'{certificate_signing_request.certificate_type}', RuntimeWarning)
        # if subject not in (None, certificate_signing_request.subject):
        #     warnings.warn(f'The subject parameter is given as {subject} '
        #                   'but the certificate signing request supposes a different subject which is '
        #                   f'{certificate_signing_request.subject}', RuntimeWarning)
        # if alternative_names not in (None, certificate_signing_request.alternative_names):
        #     warnings.warn(f'The alternative_names parameter is given as {alternative_names} '
        #                   'but the certificate signing request supposes a different alternative names which are '
        #                   f'{certificate_signing_request.alternative_names}', RuntimeWarning)
        # if extra_extensions not in (None, certificate_signing_request.extra_extensions):
        #     warnings.warn(f'The extra_extensions parameter is given as {extra_extensions} '
        #                   'but the certificate signing request supposes a different extra extensions which are '
        #                   f'{certificate_signing_request.extra_extensions}', RuntimeWarning)
        # certificate_llo = self.build(
        #     builder=x509.CertificateBuilder(),
        #     issuer_private_key=issuer_private_key,
        #     issuer_subject=issuer_subject,
        #     private_key=private_key,
        #     certificate_type=certificate_type,
        #     term=term,
        #     subject=subject,
        #     alternative_names=alternative_names,
        #     extra_extensions=extra_extensions
        # )
        # certificate = Certificate(
        #     nickname=nickname,
        #     file=file,
        #     chain_file=chain_file,
        #     llo=certificate_llo,
        #     ca=ca,
        #     issuer_private_key=issuer_private_key,
        #     issuer_subject=issuer_subject,
        #     private_key=private_key,
        # )
        # certificate.anatomize_llo()
        # certificate.save()
        # certificate.save_chain()
        # return certificate
        logging.debug(f"ASSIGNED: {parameters_assigned}")
        certificate = Certificate(
            **{
                k: v for k, v in parameters_assigned.items() if k in [
                    'nickname',
                    'file',
                    'chain_file',
                    'ca',
                    'issuer_private_key',
                    'issuer_subject',
                    'private_key',
                    'subject',
                    'alternative_names',
                    'extra_extensions'
                ]
            },
            llo=self.build_llo(
                builder=x509.CertificateBuilder(),
                issuer_private_key=parameters_assigned.get('issuer_private_key'),
                issuer_subject=parameters_assigned.get('issuer_subject'),
                private_key=parameters_assigned.get('private_key'),
                certificate_type=parameters_assigned.get('certificate_type'),
                term=parameters_assigned.get('term'),
                subject=parameters_assigned.get('subject'),
                alternative_names=parameters_assigned.get('alternative_names'),
                extra_extensions=parameters_assigned.get('extra_extensions')
        ))
        certificate.anatomize_llo()
        certificate.save()
        certificate.save_chain()
        return certificate
