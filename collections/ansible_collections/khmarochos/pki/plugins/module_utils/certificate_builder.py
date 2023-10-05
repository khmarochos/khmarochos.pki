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
    'certificate_type': {'type': CertificateTypes, 'default': CertificateTypes.CLIENT},
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

    def init_with_file(
            self,
            nickname: str = None,
            file: str = None,
            private_key: PrivateKey = None,
    ) -> Certificate:
        if (nickname := self._from_kwargs_or_properties('nickname')) is None:
            raise ValueError('The nickname parameter cannot be None')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if (private_key := self._from_kwargs_or_properties('private_key')) is None:
            raise ValueError('The private_key parameter cannot be None')
        certificate = Certificate(nickname=nickname, file=file, private_key=private_key)
        certificate.load()
        certificate.anatomize_llo()
        return certificate

    def init_with_llo(
            self,
            nickname: str = None,
            llo: x509.Certificate = None,
    ):
        pass

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
    ) -> Certificate:
        if (nickname := self._from_kwargs_or_properties('nickname')) is None:
            raise ValueError('The nickname parameter cannot be None')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if (chain_file := self._from_kwargs_or_properties('chain_file')) is None:
            pass
        if (certificate_type := self._from_kwargs_or_properties('certificate_type')) is None:
            pass
        if (term := self._from_kwargs_or_properties('term')) is None:
            pass
        if (private_key := self._from_kwargs_or_properties('private_key')) is None:
            raise ValueError('The private_key parameter cannot be None')
        if (subject := self._from_kwargs_or_properties('subject')) is None:
            raise ValueError('The subject parameter cannot be None')
        if (alternative_names := self._from_kwargs_or_properties('alternative_names')) is None:
            alternative_names = []
        if (extra_extensions := self._from_kwargs_or_properties('extra_extensions')) is None:
            extra_extensions = []
        if (issuer_private_key := self._from_kwargs_or_properties('issuer_private_key')) is None:
            pass
        if (issuer_subject := self._from_kwargs_or_properties('issuer_subject')) is None:
            pass
        if (ca := self._from_kwargs_or_properties('ca')) is not None:
            if issuer_private_key is None:
                issuer_private_key = ca.certificate.private_key
            elif issuer_private_key != ca.certificate.private_key:
                warnings.warn(f'The ca_private_key parameter is given as {issuer_private_key} '
                              f'but the CA has a different private key which is '
                              f'{ca.certificate.private_key}', RuntimeWarning)
            if issuer_subject is None:
                issuer_subject = ca.certificate.subject
            elif issuer_subject != ca.certificate.subject:
                warnings.warn(f'The ca_subject parameter is given as {issuer_subject} '
                              'but the CA has a different subject which is '
                              f'{ca.certificate.subject}', RuntimeWarning)
        if issuer_private_key is None:
            issuer_private_key = private_key
        if issuer_subject is None:
            issuer_subject = subject
        certificate = Certificate(
            nickname=nickname,
            file=file,
            chain_file=chain_file,
            llo=self.build(
                builder=x509.CertificateBuilder(),
                issuer_private_key=issuer_private_key,
                issuer_subject=issuer_subject,
                private_key=private_key,
                certificate_type=certificate_type,
                term=term,
                subject=subject,
                alternative_names=alternative_names,
                extra_extensions=extra_extensions
            ),
            certificate_type=certificate_type,
            term=term,
            ca=ca,
            issuer_private_key=issuer_private_key,
            issuer_subject=issuer_subject,
            subject=subject,
            alternative_names=alternative_names,
            extra_extensions=extra_extensions,
            private_key=private_key,
        )
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
        # Fetch parameters from the method's arguments or from the builder's properties
        if (nickname := self._from_kwargs_or_properties('nickname')) is None:
            raise ValueError('The nickname parameter cannot be None')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if (chain_file := self._from_kwargs_or_properties('chain_file')) is None:
            pass
        if (certificate_type := self._from_kwargs_or_properties('certificate_type')) is None:
            pass
        if (term := self._from_kwargs_or_properties('term')) is None:
            raise ValueError('The term parameter cannot be None')
        if (certificate_signing_request := self._from_kwargs_or_properties('certificate_signing_request')) is None:
            raise ValueError('The certificate_signing_request parameter cannot be None')
        if (private_key := self._from_kwargs_or_properties('private_key')) is None:
            private_key = certificate_signing_request.private_key
        if (subject := self._from_kwargs_or_properties('subject')) is None:
            subject = certificate_signing_request.subject
        if (alternative_names := self._from_kwargs_or_properties('alternative_names')) is None:
            alternative_names = certificate_signing_request.alternative_names
        if (extra_extensions := self._from_kwargs_or_properties('extra_extensions')) is None:
            extra_extensions = certificate_signing_request.extra_extensions
        if (issuer_private_key := self._from_kwargs_or_properties('issuer_private_key')) is None:
            pass
        if (issuer_subject := self._from_kwargs_or_properties('issuer_subject')) is None:
            pass
        if (ca := self._from_kwargs_or_properties('ca')) is not None:
            if issuer_private_key is None:
                issuer_private_key = ca.certificate.private_key
            elif issuer_private_key != ca.certificate.private_key:
                warnings.warn(f'The ca_private_key parameter is given as {issuer_private_key} '
                              f'but the CA has a different private key which is '
                              f'{ca.certificate.private_key}', RuntimeWarning)
            if issuer_subject is None:
                issuer_subject = ca.certificate.subject
            elif issuer_subject != ca.certificate.subject:
                warnings.warn(f'The ca_subject parameter is given as {issuer_subject} '
                              'but the CA has a different subject which is '
                              f'{ca.certificate.subject}', RuntimeWarning)
        if issuer_private_key is None:
            issuer_private_key = private_key
        if issuer_subject is None:
            issuer_subject = subject
        # Perform some sanity checks
        if private_key not in (None, certificate_signing_request.private_key):
            warnings.warn(f'The private_key parameter is given as {private_key} '
                          f'but the certificate signing request supposes a different private key which is '
                          f'{certificate_signing_request.private_key}', RuntimeWarning)
        if certificate_type not in (None, certificate_signing_request.certificate_type):
            warnings.warn(f'The certificate_type parameter is given as {certificate_type} '
                          'but the certificate signing request supposes a different type which is '
                          f'{certificate_signing_request.certificate_type}', RuntimeWarning)
        if subject not in (None, certificate_signing_request.subject):
            warnings.warn(f'The subject parameter is given as {subject} '
                          'but the certificate signing request supposes a different subject which is '
                          f'{certificate_signing_request.subject}', RuntimeWarning)
        if alternative_names not in (None, certificate_signing_request.alternative_names):
            warnings.warn(f'The alternative_names parameter is given as {alternative_names} '
                          'but the certificate signing request supposes a different alternative names which are '
                          f'{certificate_signing_request.alternative_names}', RuntimeWarning)
        if extra_extensions not in (None, certificate_signing_request.extra_extensions):
            warnings.warn(f'The extra_extensions parameter is given as {extra_extensions} '
                          'but the certificate signing request supposes a different extra extensions which are '
                          f'{certificate_signing_request.extra_extensions}', RuntimeWarning)
        certificate = Certificate(
            nickname=nickname,
            file=file,
            chain_file=chain_file,
            llo=self.build(
                builder=x509.CertificateBuilder(),
                issuer_private_key=issuer_private_key,
                issuer_subject=issuer_subject,
                private_key=private_key,
                certificate_type=certificate_type,
                term=term,
                subject=subject,
                alternative_names=alternative_names,
                extra_extensions=extra_extensions
            ),
            certificate_type=certificate_type,
            term=term,
            ca=ca,
            issuer_private_key=issuer_private_key,
            issuer_subject=issuer_subject,
            subject=subject,
            alternative_names=alternative_names,
            extra_extensions=extra_extensions,
            private_key=private_key,
        )
        certificate.save()
        certificate.save_chain()
        return certificate
