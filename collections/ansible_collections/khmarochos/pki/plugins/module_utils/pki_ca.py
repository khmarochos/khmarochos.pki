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

import os.path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate import Certificate
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import \
    CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.key import Key
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


# noinspection PyCompatibility
class PKICA(FlexiClass, properties={
    # default parameters for parameters' definitions
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'type': str,
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.ON_SET,
    },
    # PKICascade
    'pki_cascade': {'type': 'ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade.PKICascade', 'mandatory': True},
    # global parameters
    'nickname': {'mandatory': True},
    'name': {'default': '${nickname} Certificate Authority'},
    'parent_nickname': {'readonly': True},
    'default': {'type': bool, 'default': False},
    'domain': {'mandatory': True},
    'strict': {'type': bool, 'default': False},
    'stubby': {'type': bool, 'default': False},
    # CA key parameters
    'key': {'type': Key},
    'key_llo': {'type': rsa.RSAPrivateKey},
    'key_size': {'type': int, 'default': Constants.DEFAULT_KEY_SIZE},
    'key_public_exponent': {'type': int, 'default': Constants.DEFAULT_KEY_PUBLIC_EXPONENT},
    'key_encrypted': {'type': bool, 'default': Constants.DEFAULT_KEY_ENCRYPTED},
    'key_passphrase': {'type': Passphrase},
    'key_passphrase_value': {'interpolate': FlexiClass.InterpolatorBehaviour.NEVER},
    'key_passphrase_random': {'type': bool, 'default': Constants.DEFAULT_PASSPHRASE_RANDOM},
    'key_passphrase_length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'key_passphrase_character_set': {'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET},
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
    'certificate_subject_country': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'certificate_subject_state_or_province': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'certificate_subject_locality': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'certificate_subject_organization': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'certificate_subject_organizational_unit': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
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
    'ca_file_prefix': {'default': 'CA_${nickname}'},
    'key_file_suffix': {'default': '.key'},
    'key_passphrase_file_suffix': {'default': '.key_passphrase'},
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
    'key_file': {
        'default':
            '${private_directory}/${ca_file_prefix}${key_file_suffix}'
    },
    'key_passphrase_file': {
        'default':
            '${private_directory}/${ca_file_prefix}${key_passphrase_file_suffix}'
    },
    'keystore_file': {
        'default':
            '${private_directory}/${ca_file_prefix}${keystore_file_suffix}'
    },
    'keystore_passphrase_file': {
        'default':
            '${private_directory}/${ca_file_prefix}${keystore_passphrase_file_suffix}'
    },
    'certificate_signing_request_file': {
        'default':
            '${certificate_signing_requests_directory}/${ca_file_prefix}${certificate_signing_request_file_suffix}'
    },
    'certificate_file': {
        'default':
            '${certificates_directory}/${ca_file_prefix}${certificate_file_suffix}'
    },
    'certificate_chain_file': {
        'default':
            '${certificates_directory}/${ca_file_prefix}${certificate_chain_file_suffix}'
    },
}):

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        property_bindings = {
            'file': 'certificate_file',
            'chain_file': 'certificate_chain_file',
            'llo': 'certificate_llo',
            'term': 'certificate_term',
            'subject_country': 'certificate_subject_country',
            'subject_state_or_province': 'certificate_subject_state_or_province',
            'subject_locality': 'certificate_subject_locality',
            'subject_organization': 'certificate_subject_organization',
            'subject_organizational_unit': 'certificate_subject_organizational_unit',
            'subject_email_address': 'certificate_subject_email_address',
            'subject_common_name': 'certificate_subject_common_name',
            'key': 'key',
            'key_llo': 'key_llo',
            'key_file': 'key_file',
            'key_size': 'key_size',
            'key_public_exponent': 'key_public_exponent',
            'key_encrypted': 'key_encrypted',
            'key_passphrase': 'key_passphrase',
            'key_passphrase_file': 'key_passphrase_file',
            'key_passphrase_value': 'key_passphrase_value',
            'key_passphrase_random': 'key_passphrase_random',
            'key_passphrase_length': 'key_passphrase_length',
            'key_passphrase_character_set': 'key_passphrase_character_set',
            # 'keystore_file': 'keystore_file',
            # 'keystore_passphrase': 'keystore_passphrase',
            # 'keystore_passphrase_file': 'keystore_passphrase_file',
            'certificate_signing_request_file': 'certificate_signing_request_file',
        }

        if self.certificate is None:
            with self.ignore_readonly('certificate'):
                self.certificate = Certificate(
                    type=CertificateTypes.CA_STUBBY if self.stubby else CertificateTypes.CA_INTERMEDIATE,
                    ca=self.pki_cascade.get_ca(self.parent_nickname) if self.parent_nickname is not None else None,
                    ** self._bind_arguments(property_bindings),
                )

        self._bind_properties([{
            'object': self.certificate,
            'properties': property_bindings,
        }])

    def setup(self):
        self.setup_directories()
        self.certificate.certificate_signing_request.key.passphrase.setup()
        self.certificate.certificate_signing_request.key.setup()
        self.certificate.certificate_signing_request.setup()
        self.certificate.setup()

    def setup_directories(self):
        for directory, mode in {
            self.root_directory:
                Constants.DEFAULT_ROOT_DIRECTORY_MODE,
            self.private_directory:
                Constants.DEFAULT_PRIVATE_DIRECTORY_MODE,
            self.certificate_signing_requests_directory:
                Constants.DEFAULT_CERTIFICATE_SIGNING_REQUESTS_DIRECTORY_MODE,
            self.certificates_directory:
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
