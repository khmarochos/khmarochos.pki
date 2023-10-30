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

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes


class CertificateBase:

    def anatomize_llo(self):
        if isinstance(self.llo, x509.Certificate):
            with self.ignore_readonly('term'):
                self.term = (self.llo.not_valid_after - self.llo.not_valid_before).days
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
                    for alternative_name in extension.value:
                        if isinstance(alternative_name, x509.DNSName):
                            self.alternative_names.append(alternative_name.value)
            elif extension.oid == x509.oid.ExtensionOID.KEY_USAGE:
                pass
            elif extension.oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
                pass
            elif extension.oid == x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                pass
            elif extension.oid == x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                pass
            else:
                with self.ignore_readonly('extra_extensions'):
                    self.extra_extensions.append(
                        {
                            'purpose': None,
                            'critical': extension.critical,
                            'extension': extension.value
                        }
                    )


    def save(self):
        with open(self.file, 'wb') as f:
            f.write(self.get_pem())


    def get_pem(self):
        return self.llo.public_bytes(serialization.Encoding.PEM)