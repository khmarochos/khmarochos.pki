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

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.key import Key
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


class CertificateSigningRequest(FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
        'type': str
    },
    'llo': {'type': x509.CertificateSigningRequest},
    'file': {'mandatory': True},
    'type': {'type': CertificateTypes, 'mandatory': True},
    'subject_country': {'mandatory': True},
    'subject_state_or_province': {'mandatory': True},
    'subject_locality': {'mandatory': True},
    'subject_organization': {'mandatory': True},
    'subject_organizational_unit': {'mandatory': True},
    'subject_email_address': {'mandatory': True},
    'subject_common_name': {'mandatory': True},
    'subject': {'type': x509.name.Name},
    'attributes': {'type': list},
    'key': {'type': Key},
    'key_llo': {'type': rsa.RSAPrivateKey},
    'key_file': {'mandatory_unless': 'key'},
    'key_size': {'type': int, 'default': Constants.DEFAULT_KEY_SIZE},
    'key_public_exponent': {'type': int, 'default': Constants.DEFAULT_KEY_PUBLIC_EXPONENT},
    'key_encrypted': {'type': bool, 'default': Constants.DEFAULT_KEY_ENCRYPTED},
    'key_passphrase': {'type': Passphrase},
    'key_passphrase_value': {},
    'key_passphrase_file': {},
    'key_passphrase_random': {'type': bool, 'default': Constants.DEFAULT_PASSPHRASE_RANDOM},
    'key_passphrase_length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'key_passphrase_character_set': {'type': str, 'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET},
}):

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        property_bindings = {
            'llo': 'key_llo',
            'file': 'key_file',
            'size': 'key_size',
            'public_exponent': 'key_public_exponent',
            'encrypted': 'key_encrypted',
            'passphrase': 'key_passphrase',
            'passphrase_value': 'key_passphrase_value',
            'passphrase_file': 'key_passphrase_file',
            'passphrase_random': 'key_passphrase_random',
            'passphrase_length': 'key_passphrase_length',
            'passphrase_character_set': 'key_passphrase_character_set',
        }

        if self.key is None:
            with self.ignore_readonly('key'):
                self.key = Key(** self._bind_arguments(property_bindings))

        self._bind_properties([{
            'object': self.key,
            'properties': property_bindings
        }])

        if self.subject is None:
            subject_name = []
            if self.subject_country is not None:
                subject_name.append(
                    x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, self.subject_country))
            if self.subject_state_or_province is not None:
                subject_name.append(
                    x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, self.subject_state_or_province))
            if self.subject_locality is not None:
                subject_name.append(
                    x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, self.subject_locality))
            if self.subject_organization is not None:
                subject_name.append(
                    x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, self.subject_organization))
            if self.subject_organizational_unit is not None:
                subject_name.append(
                    x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, self.subject_organizational_unit))
            if self.subject_email_address is not None:
                subject_name.append(
                    x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, self.subject_email_address))
            if self.subject_common_name is not None:
                subject_name.append(
                    x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, self.subject_common_name))
            with self.ignore_readonly('subject'):
                self.subject = x509.Name(subject_name)

        if self.attributes is None:
            attributes = []
            if self.type == CertificateTypes.CA_STUBBY:
                attributes.append(
                    x509.Extension(x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
                                   True,
                                   x509.BasicConstraints(ca=True, path_length=0)))
            elif self.type == CertificateTypes.CA_INTERMEDIATE:
                attributes.append(
                    x509.Extension(x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
                                   True,
                                   x509.BasicConstraints(ca=True, path_length=None)))
            with self.ignore_readonly('attributes'):
                self.attributes = attributes


    def setup(self):
        self.setup_llo()

    def setup_llo(self, force_save: bool = False, force_load: bool = False):
        generated = False
        if getattr(self, 'llo') is None or force_load:
            try:
                self.load_llo()
            except FileNotFoundError:
                self.make_llo()
                generated = True
        if generated or force_save:
            self.save_llo()

    def load_llo(self):
        with open(self.file, 'rb') as f, self.ignore_readonly('llo'):
            self.llo = x509.load_pem_x509_csr(f.read())

    def make_llo(self):
        with self.ignore_readonly('llo'):
            self.llo = x509.CertificateSigningRequestBuilder(
                subject_name=x509.Name(self.subject),
                # attributes=self.attributes
            ).sign(
                private_key=self.key.llo,
                algorithm=hashes.SHA256()
            )

    def save_llo(self):
        with open(self.file, 'wb') as f:
            f.write(self.llo.public_bytes(serialization.Encoding.PEM))