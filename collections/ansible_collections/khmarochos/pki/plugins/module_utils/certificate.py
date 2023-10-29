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


import datetime
import logging
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey


class Certificate(FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
        'type': str
    },
    'nickname': {'mandatory': True},
    'llo': {'type': x509.Certificate},
    'file': {'mandatory': True},
    'chain_file': {},
    'certificate_type': {'type': CertificateTypes},
    'term': {'type': int},
    'ca': {'type': 'ansible_collections.khmarochos.pki.plugins.module_utils.pki_ca.PKICA'},
    'issuer_private_key': {'type': PrivateKey},
    'issuer_subject': {'type': x509.name.Name},
    'subject': {'type': x509.name.Name},
    'alternative_names': {'type': list},
    'extra_extensions': {'type': list},
    'private_key': {'type': PrivateKey},
}):

    def load(self, anatomize_llo: bool = True):
        with open(self.file, 'rb') as f, self.ignore_readonly('llo'):
            self.llo = x509.load_pem_x509_certificate(f.read())
        if anatomize_llo:
            self.anatomize_llo()

    def anatomize_llo(self):
        logging.debug(f'Anatomizing certificate {self}')
        with self.ignore_readonly('term'):
            logging.debug(f'not_valid_after: {self.llo.not_valid_after}')
            logging.debug(f'not_valid_before: {self.llo.not_valid_before}')
            self.term = (self.llo.not_valid_after - self.llo.not_valid_before).days
            logging.debug(f'term: {self.term}')
        with self.ignore_readonly('subject'):
            self.subject = self.llo.subject
        with self.ignore_readonly('certificate_type'):
            self.certificate_type = CertificateTypes.CLIENT
        with self.ignore_readonly('alternative_names'):
            self.alternative_names = []
        with self.ignore_readonly('extra_extensions'):
            self.extra_extensions = []
        for extension in self.llo.extensions:
            if extension.oid == x509.oid.ExtensionOID.BASIC_CONSTRAINTS:
                with self.ignore_readonly('certificate_type'):
                    if extension.value.ca:
                        if extension.value.path_length == 0:
                            self.certificate_type = CertificateTypes.CA_STUBBY
                        else:
                            self.certificate_type = CertificateTypes.CA_INTERMEDIATE
            elif extension.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                with self.ignore_readonly('alternative_names'):
                    self.alternative_names = extension.value.get_values_for_type(x509.DNSName)
            else:
                with self.ignore_readonly('extensions'):
                    self.extra_extensions.append(
                        {
                            'purpose': None,
                            'critical': extension.critical,
                            'extension': extension.value
                        }
                    )

    def sign(self):
        certificate_builder = x509.CertificateBuilder() \
            .subject_name(self.subject) \
            .issuer_name(self.ca.certificate.subject if self.ca is not None else self.subject) \
            .public_key(self.ca.private_key.llo.public_key() if self.ca is not None else self.private_key.llo.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=self.term))
        for extension in self.extra_extensions:
            certificate_builder = certificate_builder.add_extension(
                extension['extension'],
                extension['critical']
            )
        with self.ignore_readonly('llo'):
            self.llo = certificate_builder.sign(
                private_key=self.ca.private_key.llo if self.ca is not None else self.private_key.llo,
                algorithm=hashes.SHA256()
            )

    def save(self):
        with open(self.file, 'wb') as f:
            f.write(self.get_pem())

    def save_chain(self):
        if self.chain_file is not None:
            with open(self.chain_file, 'wb') as f:
                f.write(self.get_pem_chain())

    def get_pem_chain(self):
        return self.get_pem() + (self.ca.certificate.get_pem_chain() if self.ca is not None else b'')

    def get_pem(self):
        return self.llo.public_bytes(encoding=serialization.Encoding.PEM)
