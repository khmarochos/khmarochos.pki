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

import logging
import os.path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_builder import CertificateBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_builder_base import CertificateBuilderBase
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request_builder import \
    CertificateSigningRequestBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangeTracker
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate import Certificate
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import \
    CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase_builder import PassphraseBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key_builder import PrivateKeyBuilder


# noinspection PyCompatibility
class PKICA(ChangeTracker, FlexiClass, properties={
    # default parameters for parameters' definitions
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'type': str,
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.ON_SET,
    },
    # global parameters
    'nickname': {'mandatory': True},
    'name': {'default': '${nickname} Certificate Authority'},
    'parent': {'type': 'ansible_collections.khmarochos.pki.plugins.module_utils.pki_ca.PKICA'},
    # 'parent_nickname': {'readonly': True},
    'default': {'type': bool, 'default': False},
    'domain': {'mandatory': True},
    'strict': {'type': bool, 'default': False},
    'stubby': {'type': bool, 'default': False},
    # CA key parameters
    'private_key': {'type': PrivateKey},
    'private_private_key_llo': {'type': rsa.RSAPrivateKey},
    'private_key_size': {'type': int, 'default': Constants.DEFAULT_PRIVATE_KEY_SIZE},
    'private_key_public_exponent': {'type': int, 'default': Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT},
    'private_key_encrypted': {'type': bool, 'default': Constants.DEFAULT_PRIVATE_KEY_ENCRYPTED},
    'private_key_passphrase': {'type': Passphrase},
    'private_key_passphrase_value': {'interpolate': FlexiClass.InterpolatorBehaviour.NEVER},
    'private_key_passphrase_random': {'type': bool, 'default': Constants.DEFAULT_PASSPHRASE_RANDOM},
    'private_key_passphrase_length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'private_key_passphrase_character_set': {'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET},
    # CA keystore parameters
    'keystore_passphrase': {'type': Passphrase},
    'keystore_passphrase_value': {'interpolate': FlexiClass.InterpolatorBehaviour.NEVER},
    'keystore_passphrase_random': {'type': bool, 'default': Constants.DEFAULT_PASSPHRASE_RANDOM},
    'keystore_passphrase_length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'keystore_passphrase_character_set': {'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET},
    # CA certificate parameters
    'certificate_signing_request': {'type': CertificateSigningRequest},
    'certificate_signing_request_llo': {'type': x509.CertificateSigningRequest},
    'certificate': {'type': Certificate},
    'certificate_llo': {'type': x509.Certificate},
    'certificate_term': {'type': int, 'default': Constants.DEFAULT_CERTIFICATE_TERM},
    'certificate_subject': {'type': x509.name.Name},
    'certificate_subject_country_name': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'certificate_subject_state_or_province_name': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'certificate_subject_locality_name': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'certificate_subject_organization_name': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'certificate_subject_organizational_unit_name': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'certificate_subject_email_address': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'certificate_subject_common_name': {'default': "${name}"},
    # directory names
    'global_root_directory': {'mandatory': True},
    'root_directory': {'default': '${global_root_directory}/${nickname}'},
    'private_directory': {'default': '${root_directory}/private'},
    'certificate_signing_requests_directory': {'default': '${root_directory}/csr'},
    'certificates_directory': {'default': '${root_directory}/certs'},
    'certificate_revocation_lists_directory': {'default': '${root_directory}/crl'},
    # filename parts
    'ca_subdirectory': {'default': 'CA'},
    'private_key_file_suffix': {'default': '.key'},
    'private_key_passphrase_file_suffix': {'default': '.key_passphrase'},
    'keystore_file_suffix': {'default': '.keystore'},
    'keystore_passphrase_file_suffix': {'default': '.keystore_passphrase'},
    'certificate_signing_request_file_suffix': {'default': '.csr'},
    'certificate_file_suffix': {'default': '.crt'},
    'certificate_chain_file_suffix': {'default': '.chain.crt'},
    # filenames
    'openssl_configuration_file': {
        'default':
            '${root_directory}/openssl.cnf'
    },
    'ca_private_key_file': {
        'default':
            '${private_directory}/${ca_subdirectory}/${nickname}${private_key_file_suffix}'
    },
    'ca_private_key_passphrase_file': {
        'default':
            '${private_directory}/${ca_subdirectory}/${nickname}${private_key_passphrase_file_suffix}'
    },
    'keystore_file': {
        'default':
            '${private_directory}/${ca_subdirectory}/${nickname}${keystore_file_suffix}'
    },
    'keystore_passphrase_file': {
        'default':
            '${private_directory}/${ca_subdirectory}/${nickname}${keystore_passphrase_file_suffix}'
    },
    'certificate_signing_request_file': {
        'default':
            '${certificate_signing_requests_directory}/${ca_subdirectory}/'
            '${nickname}${certificate_signing_request_file_suffix}'
    },
    'certificate_file': {
        'default':
            '${certificates_directory}/${ca_subdirectory}/${nickname}${certificate_file_suffix}'
    },
    'certificate_chain_file': {
        'default':
            '${certificates_directory}/${ca_subdirectory}/${nickname}${certificate_chain_file_suffix}'
    },
}):

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        if self.certificate_subject is None:
            if self.certificate_subject_common_name is None:
                with self.ignore_readonly('certificate_subject_common_name'):
                    self.certificate_subject_common_name = self.name
            with self.ignore_readonly('certificate_subject'):
                self.certificate_subject = CertificateBuilderBase.compose_subject(
                    country_name=self.certificate_subject_country_name,
                    state_or_province_name=self.certificate_subject_state_or_province_name,
                    locality_name=self.certificate_subject_locality_name,
                    organization_name=self.certificate_subject_organization_name,
                    organizational_unit_name=self.certificate_subject_organizational_unit_name,
                    email_address=self.certificate_subject_email_address,
                    common_name=self.certificate_subject_common_name
                )

    def setup(
            self,
            load_if_exists: bool = True,
            save_if_needed: bool = True,
            save_forced: bool = False
    ):
        self.setup_directories()
        if self.private_key_passphrase is None and self.private_key_encrypted:
            with self.ignore_readonly('private_key_passphrase'):
                self.private_key_passphrase = PassphraseBuilder(changes_stack=self.changes_stack) \
                    .init_with_random(
                        file=self.ca_private_key_passphrase_file,
                        load_if_exists=load_if_exists,
                        save_if_needed=save_if_needed,
                        save_forced=save_forced
                    )
        if self.private_key is None:
            with self.ignore_readonly('private_key'):
                self.private_key = PrivateKeyBuilder(changes_stack=self.changes_stack) \
                    .init_new(
                        nickname=self.nickname,
                        file=self.ca_private_key_file,
                        size=self.private_key_size,
                        encrypted=self.private_key_encrypted,
                        passphrase=self.private_key_passphrase,
                        load_if_exists=load_if_exists,
                        save_if_needed=save_if_needed,
                        save_forced=save_forced
                    )
        if self.certificate_signing_request is None:
            with self.ignore_readonly('certificate_signing_request'):
                self.certificate_signing_request = CertificateSigningRequestBuilder(changes_stack=self.changes_stack) \
                    .init_new(
                        nickname=self.nickname,
                        file=self.certificate_signing_request_file,
                        private_key=self.private_key,
                        certificate_type=CertificateTypes.CA_INTERMEDIATE,
                        subject=self.certificate_subject,
                        alternative_names=None,
                        extra_extensions=None,
                        load_if_exists=load_if_exists,
                        save_if_needed=save_if_needed,
                        save_forced=save_forced
                    )
        if self.certificate is None:
            with self.ignore_readonly('certificate'):
                self.certificate = CertificateBuilder(changes_stack=self.changes_stack).sign_csr(
                        nickname=self.nickname,
                        file=self.certificate_file,
                        certificate_type=CertificateTypes.CA_INTERMEDIATE,
                        term=self.certificate_term,
                        ca=self.parent,
                        subject=self.certificate_subject,
                        alternative_names=None,
                        extra_extensions=None,
                        private_key=self.private_key,
                        certificate_signing_request=self.certificate_signing_request,
                        load_if_exists=load_if_exists,
                        save_if_needed=save_if_needed,
                        save_forced=save_forced
                    )

    def setup_directories(self):
        for directory, mode in {
            self.root_directory:
                Constants.DEFAULT_ROOT_DIRECTORY_MODE,
            self.private_directory:
                Constants.DEFAULT_PRIVATE_DIRECTORY_MODE,
            self.private_directory + '/' + self.ca_subdirectory:
                Constants.DEFAULT_PRIVATE_DIRECTORY_MODE,
            self.certificate_signing_requests_directory:
                Constants.DEFAULT_CERTIFICATE_SIGNING_REQUESTS_DIRECTORY_MODE,
            self.certificate_signing_requests_directory + '/' + self.ca_subdirectory:
                Constants.DEFAULT_CERTIFICATE_SIGNING_REQUESTS_DIRECTORY_MODE,
            self.certificates_directory:
                Constants.DEFAULT_CERTIFICATES_DIRECTORY_MODE,
            self.certificates_directory + '/' + self.ca_subdirectory:
                Constants.DEFAULT_CERTIFICATES_DIRECTORY_MODE,
            self.certificate_revocation_lists_directory:
                Constants.DEFAULT_CERTIFICATE_REVOCATION_LISTS_DIRECTORY_MODE
        }.items():
            if os.path.exists(directory):
                if not os.path.isdir(directory):
                    raise Exception(f"Path '{directory}' exists but is not a directory")
                if not os.stat(directory).st_mode & mode == mode:
                    raise Exception(f"Path '{directory}' exists but has wrong permissions")
            else:
                os.makedirs(directory, mode=mode)
                self.changes_stack.state(f"Directory '{directory}' created")

    def issue(
            self,
            nickname: str,
            certificate_file: str = None,
            certificate_llo: x509.Certificate = None,
            certificate_chain_file: str = None,
            certificate_type: CertificateTypes = None,
            certificate_term: int = None,
            certificate_subject_country: str = None,
            certificate_subject_state_or_province: str = None,
            certificate_subject_locality: str = None,
            certificate_subject_organization: str = None,
            certificate_subject_organizational_unit: str = None,
            certificate_subject_email_address: str = None,
            certificate_subject_common_name: str = None,
            certificate_subject: x509.name.Name = None,
            certificate_alternative_names: list[str] = None,
            certificate_extensions: list[str] = None,
            certificate_signing_request: CertificateSigningRequest = None,
            certificate_signing_request_llo: x509.CertificateSigningRequest = None,
            certificate_signing_request_file: str = None,
            private_key: PrivateKey = None,
            private_key_llo: rsa.RSAPrivateKey = None,
            private_key_file: str = None,
            private_key_size: int = None,
            private_key_public_exponent: int = None,
            private_key_encrypted: bool = None,
            private_key_passphrase: Passphrase = None,
            private_key_passphrase_file: str = None,
            private_key_passphrase_value: str = None,
            private_key_passphrase_random: bool = None,
            private_key_passphrase_length: int = None,
            private_key_passphrase_character_set: str = None,
            load_if_exists: bool = True,
            save_if_needed: bool = True,
            save_forced: bool = False
    ) -> Certificate:
        if certificate_signing_request is None:
            if private_key is None:
                if private_key_passphrase is None:
                    if private_key_passphrase_file is None:
                        private_key_passphrase_file = self.form_filename(
                            nickname,
                            Passphrase,
                            suffix=self.private_key_passphrase_file_suffix
                        )
                    if private_key_passphrase_random:
                        private_key_passphrase = PassphraseBuilder(changes_stack=self.changes_stack) \
                            .init_with_random(
                                file=private_key_passphrase_file,
                                length=private_key_passphrase_length,
                                character_set=private_key_passphrase_character_set,
                                load_if_exists=load_if_exists,
                                save_if_needed=save_if_needed,
                                save_forced=save_forced
                            )
                    elif private_key_passphrase_value is not None:
                        private_key_passphrase = PassphraseBuilder(changes_stack=self.changes_stack) \
                            .init_with_value(
                                file=private_key_passphrase_file,
                                value=private_key_passphrase_value,
                                load_if_exists=load_if_exists,
                                save_if_needed=save_if_needed,
                                save_forced=save_forced
                            )
                    else:
                        private_key_passphrase = PassphraseBuilder(changes_stack=self.changes_stack) \
                            .init_with_file(
                                file=private_key_passphrase_file,
                            )
                if private_key_file is None:
                    private_key_file = self.form_filename(
                        nickname,
                        PrivateKey,
                        suffix=self.private_key_file_suffix
                    )
                if private_key_llo is None:
                    private_key = PrivateKeyBuilder(changes_stack=self.changes_stack) \
                        .init_new(
                            nickname=nickname,
                            file=private_key_file,
                            size=private_key_size,
                            public_exponent=private_key_public_exponent,
                            encrypted=private_key_encrypted,
                            passphrase=private_key_passphrase,
                            load_if_exists=load_if_exists,
                            save_if_needed=save_if_needed,
                            save_forced=save_forced
                        )
                else:
                    private_key = PrivateKeyBuilder(changes_stack=self.changes_stack) \
                        .init_with_llo(
                            nickname=nickname,
                            file=private_key_file,
                            llo=private_key_llo,
                            encrypted=private_key_encrypted,
                            passphrase=private_key_passphrase,
                            load_if_exists=load_if_exists,
                            save_if_needed=save_if_needed,
                            save_forced=save_forced
                        )
            if certificate_signing_request_file is None:
                certificate_signing_request_file = self.form_filename(
                    nickname,
                    CertificateSigningRequest,
                    suffix=self.certificate_signing_request_file_suffix
                )
            if certificate_subject is None:
                if certificate_subject_common_name is None:
                    certificate_subject_common_name = nickname
                certificate_subject = CertificateBuilderBase.compose_subject(
                    country_name=certificate_subject_country,
                    state_or_province_name=certificate_subject_state_or_province,
                    locality_name=certificate_subject_locality,
                    organization_name=certificate_subject_organization,
                    organizational_unit_name=certificate_subject_organizational_unit,
                    email_address=certificate_subject_email_address,
                    common_name=certificate_subject_common_name
                )
            if certificate_signing_request_llo is None:
                certificate_signing_request = CertificateSigningRequestBuilder(changes_stack=self.changes_stack) \
                    .init_new(
                        nickname=nickname,
                        file=certificate_signing_request_file,
                        private_key=private_key,
                        certificate_type=certificate_type,
                        subject=certificate_subject,
                        alternative_names=certificate_alternative_names,
                        extra_extensions=certificate_extensions,
                        load_if_exists=load_if_exists,
                        save_if_needed=save_if_needed,
                        save_forced=save_forced
                    )
            else:
                certificate_signing_request = CertificateSigningRequestBuilder(changes_stack=self.changes_stack) \
                    .init_with_llo(
                        nickname=nickname,
                        file=certificate_signing_request_file,
                        llo=certificate_signing_request_llo,
                        private_key=private_key,
                        save=True
                    )
            CertificateBuilder._check_after_load(
                certificate_signing_request,
                {
                    'nickname': nickname,
                    'file': certificate_signing_request_file,
                    'private_key': private_key,
                    'certificate_type': certificate_type,
                    'subject': certificate_subject,
                    'alternative_names': certificate_alternative_names,
                    'extra_extensions': certificate_extensions,
                }
            )
        if certificate_file is None:
            certificate_file = self.form_filename(
                nickname,
                Certificate,
                suffix=self.certificate_file_suffix
            )
        if certificate_chain_file is None:
            certificate_chain_file = self.form_filename(
                nickname,
                Certificate,
                suffix=self.certificate_chain_file_suffix
            )
        if certificate_llo is None:
            certificate = CertificateBuilder(changes_stack=self.changes_stack) \
                .sign_csr(
                    nickname=nickname,
                    file=certificate_file,
                    chain_file=certificate_chain_file,
                    certificate_type=certificate_type,
                    term=certificate_term,
                    ca=self,
                    subject=certificate_subject,
                    alternative_names=certificate_alternative_names,
                    extra_extensions=certificate_extensions,
                    private_key=private_key,
                    certificate_signing_request=certificate_signing_request,
                    load_if_exists=load_if_exists,
                    save_if_needed=save_if_needed,
                    save_forced=save_forced,
                    save_chain=True
                )
        else:
            certificate = CertificateBuilder(changes_stack=self.changes_stack).init_with_llo(
                    nickname=nickname,
                    file=certificate_file,
                    chain_file=certificate_chain_file,
                    llo=certificate_llo,
                    save_if_needed=save_if_needed,
                    save_forced=save_forced,
                    save_chain=True
                )
        CertificateBuilder._check_after_load(
            certificate,
            {
                'nickname': nickname,
                'file': certificate_file,
                'chain_file': certificate_chain_file,
                'certificate_type': certificate_type,
                'term': certificate_term,
                'ca': self,
                'subject': certificate_subject,
                'alternative_names': certificate_alternative_names,
                'extra_extensions': certificate_extensions,
                'private_key': private_key,
                'certificate_signing_request': certificate_signing_request,
            }
        )
        return certificate

    def form_filename(
            self,
            nickname: str,
            object_type: type,
            prefix: str = None,
            suffix: str = None
    ):
        if object_type == Certificate:
            prefix = self.certificates_directory if prefix is None else prefix
            suffix = self.certificate_file_suffix if suffix is None else suffix
        elif object_type == CertificateSigningRequest:
            prefix = self.certificate_signing_requests_directory if prefix is None else prefix
            suffix = self.certificate_signing_request_file_suffix if suffix is None else suffix
        elif object_type == PrivateKey:
            prefix = self.private_directory if prefix is None else prefix
            suffix = self.private_key_file_suffix if suffix is None else suffix
        elif object_type == Passphrase:
            prefix = self.private_directory if prefix is None else prefix
            suffix = self.private_key_passphrase_file_suffix if suffix is None else suffix
        else:
            raise Exception(f"Unsupported object type '{object_type}'")
        return f"{prefix}/{nickname}{suffix}"

    def get_pem_chain(self):
        logging.debug('Getting PEM chain for CA %s', self.nickname)
        return self.certificate.get_pem() + (self.parent.get_pem_chain() if self.parent is not None else b'')
