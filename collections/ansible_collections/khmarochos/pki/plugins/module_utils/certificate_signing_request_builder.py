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
from cryptography import x509

from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import \
    CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_builder_base import CertificateBuilderBase
from ansible_collections.khmarochos.pki.plugins.module_utils.flexibuilder import FlexiBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class CertificateSigningRequestBuilder(CertificateBuilderBase, FlexiBuilder, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'type': str,
        'mandatory': False,
        'default': None,
        'readonly': False,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
        'add_builder_updater': True
    },
    'nickname': {},
    'llo': {'type': x509.CertificateSigningRequest},
    'file': {},
    'certificate_type': {'type': CertificateTypes, 'default': CertificateTypes.CLIENT},
    'subject': {'type': x509.name.Name},
    'subject_country': {},
    'subject_state_or_province': {},
    'subject_locality': {},
    'subject_organization': {},
    'subject_organizational_unit': {},
    'subject_email_address': {},
    'subject_common_name': {},
    'alternative_names': {'type': list},
    'extra_extensions': {'type': list},
    'private_key': {'type': PrivateKey}
}):

    def init_with_file(
            self,
            nickname: str = None,
            file: str = None,
            private_key: PrivateKey = None,
    ) -> CertificateSigningRequest:
        if (nickname := self._from_kwargs_or_properties('nickname')) is None:
            raise ValueError('The nickname parameter cannot be None')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if (private_key := self._from_kwargs_or_properties('private_key')) is None:
            raise ValueError('The private_key parameter cannot be None')
        certificate_signing_request = CertificateSigningRequest(nickname=nickname, file=file, private_key=private_key)
        certificate_signing_request.load()
        return certificate_signing_request

    def init_with_llo(
            self,
            nickname: str = None,
            file: str = None,
            llo: x509.CertificateSigningRequest = None,
            private_key: PrivateKey = None,
            save: bool = True
    ) -> CertificateSigningRequest:
        if (nickname := self._from_kwargs_or_properties('nickname')) is None:
            raise ValueError('The nickname parameter cannot be None')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if (llo := self._from_kwargs_or_properties('llo')) is None:
            raise ValueError('The llo parameter cannot be None')
        if (private_key := self._from_kwargs_or_properties('private_key')) is None:
            raise ValueError('The private_key parameter cannot be None')
        certificate_signing_request = CertificateSigningRequest(
            nickname=nickname,
            file=file,
            llo=llo,
            private_key=private_key
        )
        certificate_signing_request.anatomize_llo()
        if save:
            certificate_signing_request.save()
        return certificate_signing_request

    def init_new(
            self,
            nickname: str = None,
            file: str = None,
            private_key: PrivateKey = None,
            certificate_type: CertificateTypes = None,
            subject: x509.name.Name = None,
            alternative_names: list = None,
            extra_extensions: list = None,
            load_if_exists: bool = False,
            save: bool = True
    ) -> CertificateSigningRequest:
        if (nickname := self._from_kwargs_or_properties('nickname')) is None:
            raise ValueError('The nickname parameter cannot be None')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if (private_key := self._from_kwargs_or_properties('private_key')) is None:
            raise ValueError('The private_key parameter cannot be None')
        if (certificate_type := self._from_kwargs_or_properties('certificate_type')) is None:
            raise ValueError('The certificate_type parameter cannot be None')
        if (subject := self._from_kwargs_or_properties('subject')) is None:
            raise ValueError('The subject parameter cannot be None')
        if (alternative_names := self._from_kwargs_or_properties('alternative_names')) is None:
            alternative_names = []
        if (extra_extensions := self._from_kwargs_or_properties('extra_extensions')) is None:
            extra_extensions = []
        certificate_signing_request = None
        if load_if_exists and os.path.isfile(file):
            certificate_signing_request = self.init_with_file(
                nickname=nickname,
                file=file,
                private_key=private_key
            )
            if certificate_signing_request.certificate_type != certificate_type:
                raise RuntimeError(f"The certificate signing request {file} already exists, "
                                   f"its certificate type ({certificate_signing_request.certificate_type}) differs "
                                   f"from the expected certificate type ({certificate_type})")
            if certificate_signing_request.subject != subject:
                raise RuntimeError(f"The certificate signing request {file} already exists, "
                                   f"its subject ({certificate_signing_request.subject}) differs "
                                   f"from the expected subject ({subject})")
            if certificate_signing_request.llo.public_key().public_numbers().n != private_key.public_modulus:
                raise RuntimeError(f"The certificate signing request {file} already exists, "
                                   f"its public modulus ({certificate_signing_request.llo.public_key().public_numbers().n}) differs "
                                   f"from the expected private key's public modulus ({private_key.public_modulus})")
            if certificate_signing_request.alternative_names != alternative_names:
                raise RuntimeError(f"The certificate signing request {file} already exists, "
                                   f"its alternative names ({certificate_signing_request.alternative_names}) differ "
                                   f"from the expected alternative names ({alternative_names})")
            if certificate_signing_request.extra_extensions != extra_extensions:
                raise RuntimeError(f"The certificate signing request {file} already exists, "
                                   f"its extra extensions ({certificate_signing_request.extra_extensions}) differ "
                                   f"from the expected extra extensions ({extra_extensions})")
        if certificate_signing_request is None:
            certificate_signing_request = CertificateSigningRequest(
                nickname=nickname,
                file=file,
                llo=self.build(
                    builder=x509.CertificateSigningRequestBuilder(),
                    issuer_private_key=private_key,
                    issuer_subject=subject,
                    private_key=private_key,
                    certificate_type=certificate_type,
                    subject=subject,
                    alternative_names=alternative_names,
                    extra_extensions=extra_extensions
                ),
                private_key=private_key,
                certificate_type=certificate_type,
                subject=subject,
                alternative_names=alternative_names,
                extra_extensions=extra_extensions
            )
            if save:
                certificate_signing_request.save()
        return certificate_signing_request
