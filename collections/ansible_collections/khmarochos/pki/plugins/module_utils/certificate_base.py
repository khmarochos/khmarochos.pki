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

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangeTracker
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class CertificateBase:
    def anatomize_llo(self):

        BIG_NEGATIVE = -(2**32)

        if isinstance(self.llo, x509.Certificate):
            with self.ignore_readonly('term'):
                self.term = (self.llo.not_valid_after_utc - self.llo.not_valid_before_utc).days
        with \
                self.ignore_readonly('subject'), \
                self.ignore_readonly('certificate_type'), \
                self.ignore_readonly('subject_alternative_names'), \
                self.ignore_readonly('extra_extensions'):
            self.subject = self.llo.subject
            self.subject_alternative_names = None
            self.extra_extensions = None
            self.certificate_type = CertificateTypes.NONE
            certificate_type_candidates = {
                CertificateTypes.CLIENT: 0,
                CertificateTypes.SERVER: 0,
                CertificateTypes.SERVER_CLIENT: 0,
                CertificateTypes.CA_STUBBY: 0,
                CertificateTypes.CA_INTERMEDIATE: 0
            }
            for extension in self.llo.extensions:
                if extension.oid == x509.oid.ExtensionOID.BASIC_CONSTRAINTS:
                    if extension.value.ca:
                        if extension.value.path_length == 0:
                            certificate_type_candidates[CertificateTypes.CLIENT] = BIG_NEGATIVE
                            certificate_type_candidates[CertificateTypes.SERVER] = BIG_NEGATIVE
                            certificate_type_candidates[CertificateTypes.SERVER_CLIENT] = BIG_NEGATIVE
                            certificate_type_candidates[CertificateTypes.CA_STUBBY] += 1
                            certificate_type_candidates[CertificateTypes.CA_INTERMEDIATE] -= 1
                        else:
                            certificate_type_candidates[CertificateTypes.CLIENT] = BIG_NEGATIVE
                            certificate_type_candidates[CertificateTypes.SERVER] = BIG_NEGATIVE
                            certificate_type_candidates[CertificateTypes.SERVER_CLIENT] = BIG_NEGATIVE
                            certificate_type_candidates[CertificateTypes.CA_STUBBY] -= 1
                            certificate_type_candidates[CertificateTypes.CA_INTERMEDIATE] += 1
                elif extension.oid == x509.oid.ExtensionOID.KEY_USAGE:
                    if extension.value.digital_signature:
                        certificate_type_candidates[CertificateTypes.CLIENT] += 1
                        certificate_type_candidates[CertificateTypes.SERVER] += 1
                        certificate_type_candidates[CertificateTypes.SERVER_CLIENT] += 1
                        certificate_type_candidates[CertificateTypes.CA_STUBBY] += 1
                        certificate_type_candidates[CertificateTypes.CA_INTERMEDIATE] += 1
                    if extension.value.key_cert_sign:
                        certificate_type_candidates[CertificateTypes.CLIENT] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.SERVER] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.SERVER_CLIENT] += 1
                        certificate_type_candidates[CertificateTypes.CA_STUBBY] += 1
                        certificate_type_candidates[CertificateTypes.CA_INTERMEDIATE] += 1
                    if extension.value.crl_sign:
                        certificate_type_candidates[CertificateTypes.CLIENT] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.SERVER] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.SERVER_CLIENT] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.CA_STUBBY] += 1
                        certificate_type_candidates[CertificateTypes.CA_INTERMEDIATE] += 1
                    if extension.value.key_agreement:
                        certificate_type_candidates[CertificateTypes.CLIENT] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.SERVER] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.SERVER_CLIENT] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.CA_STUBBY] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.CA_INTERMEDIATE] += 1
                    if extension.value.key_encipherment:
                        certificate_type_candidates[CertificateTypes.CLIENT] += 1
                        certificate_type_candidates[CertificateTypes.SERVER] += 1
                        certificate_type_candidates[CertificateTypes.SERVER_CLIENT] += 1
                        certificate_type_candidates[CertificateTypes.CA_STUBBY] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.CA_INTERMEDIATE] = BIG_NEGATIVE
                    if extension.value.data_encipherment:
                        certificate_type_candidates[CertificateTypes.CLIENT] += 1
                        certificate_type_candidates[CertificateTypes.SERVER] += 1
                        certificate_type_candidates[CertificateTypes.SERVER_CLIENT] += 1
                        certificate_type_candidates[CertificateTypes.CA_STUBBY] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.CA_INTERMEDIATE] = BIG_NEGATIVE
                    # if extension.value.encipher_only:
                    #     pass    # ???
                    # if extension.value.encipher_only:
                    #     pass    # ???
                elif extension.oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
                    if x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in extension.value:
                        certificate_type_candidates[CertificateTypes.CA_STUBBY] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.CA_INTERMEDIATE] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.SERVER_CLIENT] += 1
                        certificate_type_candidates[CertificateTypes.SERVER] += 1
                    if x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in extension.value:
                        certificate_type_candidates[CertificateTypes.CA_STUBBY] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.CA_INTERMEDIATE] = BIG_NEGATIVE
                        certificate_type_candidates[CertificateTypes.CLIENT] += 1
                        certificate_type_candidates[CertificateTypes.SERVER_CLIENT] += 1
                elif extension.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    if self.subject_alternative_names is None:
                        self.subject_alternative_names = []
                    for subject_alternative_name in extension.value:
                        if isinstance(subject_alternative_name, x509.general_name.DNSName):
                            self.subject_alternative_names.append('DNS:' + subject_alternative_name.value)
                        elif isinstance(subject_alternative_name, x509.general_name.UniformResourceIdentifier):
                            self.subject_alternative_names.append('URI:' + subject_alternative_name.value)
                        elif isinstance(subject_alternative_name, x509.general_name.IPAddress):
                            self.subject_alternative_names.append('IP:' + subject_alternative_name.value.__str__())
                        else:
                            raise RuntimeError(f"Unknown subject alternative name type: {type(subject_alternative_name)}")
                elif extension.oid == x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                    pass
                elif extension.oid == x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                    pass
                else:
                    if self.extra_extensions is None:
                        self.extra_extensions = []
                    self.extra_extensions.append(
                        {
                            'purpose': None,
                            'critical': extension.critical,
                            'extension': extension.value
                        }
                    )
            # I don't like how it works, to be honest, though it works
            certificate_type_max_score = max(certificate_type_candidates.values())
            if (
                    certificate_type_candidates[CertificateTypes.SERVER] ==
                    certificate_type_candidates[CertificateTypes.CLIENT] ==
                    certificate_type_candidates[CertificateTypes.SERVER_CLIENT] ==
                    certificate_type_max_score and
                    certificate_type_max_score > 0
            ):
                self.certificate_type = CertificateTypes.SERVER_CLIENT
            else:
                certificate_type_candidates = {
                    certificate_type: score for certificate_type, score in certificate_type_candidates.items()
                        if score == certificate_type_max_score
                }
                if len(certificate_type_candidates) > 0 and certificate_type_max_score > 0:
                    self.certificate_type = list(certificate_type_candidates.keys())[0]
                # else:
                #     raise RuntimeError(f"Unable to determine certificate type: {format(certificate_type_candidates)}")


    def save(self):
        with open(self.file, 'wb') as f:
            f.write(self.get_pem())


    def get_pem(self):
        return self.llo.public_bytes(serialization.Encoding.PEM)