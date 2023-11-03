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
import os
from cryptography import x509

from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import \
    CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangeTracker
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_builder_base import CertificateBuilderBase
from ansible_collections.khmarochos.pki.plugins.module_utils.flexibuilder import FlexiBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class CertificateSigningRequestBuilder(ChangeTracker, CertificateBuilderBase, FlexiBuilder, properties={
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
    'alternative_names': {'type': list},
    'extra_extensions': {'type': list},
    'private_key': {'type': PrivateKey}
}):

    @FlexiBuilder.parameters_assigner
    def _assign_parameters(
            self,
            parameters_to_assign: dict = None,
            parameters_to_merge: dict = None,
            parameters_assigned: dict = None
    ) -> dict:
        return parameters_assigned

    @staticmethod
    def _check_after_load(
            certificate_signing_request: CertificateSigningRequest,
            parameters_assigned: dict,
            raise_exception: bool = True
    ) -> bool:
        result = FlexiBuilder.check_after_load_universal(
            object_to_check=certificate_signing_request,
            parameters_assigned=parameters_assigned,
            parameters_to_check=['certificate_type', 'subject', 'private_key', 'alternative_names', 'extra_extensions'],
            raise_exception=raise_exception
        )
        if certificate_signing_request.llo.public_key() != certificate_signing_request.private_key.llo.public_key():
            if raise_exception:
                raise RuntimeError(
                    f"The private key of the {certificate_signing_request.nickname} certificate signing request "
                    "differs from the public key of the private key assigned to it")
            else:
                result = False
        return result

    def init_with_file(
            self,
            nickname: str = None,
            file: str = None,
            private_key: PrivateKey = None,
    ) -> CertificateSigningRequest:
        parameters_assigned = self._assign_parameters({
            'nickname': {'mandatory': True},
            'file': {'mandatory': True},
            'private_key': {'mandatory': True},
        })
        certificate_signing_request = CertificateSigningRequest(**parameters_assigned)
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
        parameters_assigned = self._assign_parameters({
            'nickname': {'mandatory': True},
            'file': {'mandatory': True},
            'llo': {'mandatory': True},
            'private_key': {'mandatory': True},
        })
        certificate_signing_request = CertificateSigningRequest(**parameters_assigned)
        certificate_signing_request.anatomize_llo()
        CertificateSigningRequestBuilder._check_after_load(certificate_signing_request, parameters_assigned)
        if save:
            certificate_signing_request.save()
            self.changes_stack.push("Saved a certificate signing request")
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
            save_if_needed: bool = True,
            save_forced: bool = False,
    ) -> CertificateSigningRequest:
        parameters_assigned = self._assign_parameters({
            'nickname': {'mandatory': True},
            'file': {'mandatory': True},
            'private_key': {'mandatory': True},
            'certificate_type': {'mandatory': True},
            'subject': {'mandatory': True},
            'alternative_names': {},
            'extra_extensions': {},
        })
        generated = False
        if load_if_exists and os.path.exists(parameters_assigned.get('file')):
            certificate_signing_request = self.init_with_file(
                **{
                    k: v for k, v in parameters_assigned.items() if k in [
                        'nickname',
                        'file',
                        'private_key'
                    ]
                }
            )
            CertificateSigningRequestBuilder._check_after_load(certificate_signing_request, parameters_assigned)
        else:
            certificate_signing_request = CertificateSigningRequest(
                **parameters_assigned,
                llo=self.build_llo(
                    builder=x509.CertificateSigningRequestBuilder(),
                    issuer_private_key=parameters_assigned.get('private_key'),
                    issuer_subject=parameters_assigned.get('subject'),
                    private_key=parameters_assigned.get('private_key'),
                    certificate_type=parameters_assigned.get('certificate_type'),
                    subject=parameters_assigned.get('subject'),
                    alternative_names=parameters_assigned.get('alternative_names'),
                    extra_extensions=parameters_assigned.get('extra_extensions')
                ),
            )
            generated = True
        if save_forced or (save_if_needed and generated):
            certificate_signing_request.save()
            self.changes_stack.push("Saved a certificate signing request")
        return certificate_signing_request
