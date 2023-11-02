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
from cryptography.hazmat.primitives import hashes

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes, Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey


class CertificateBuilderBase:

    @staticmethod
    def compose_subject(**kwargs) -> x509.name.Name:
        components = []
        for component, value in kwargs.items():
            if value is None:
                continue
            if (name_oid := getattr(x509.oid.NameOID, component.upper(), None)) is None:
                raise ValueError(f"Unknown subject component: {component}")
            components.append(x509.NameAttribute(name_oid, value))
        if len(components) == 0:
            raise ValueError('At least one subject component must be specified')
        return x509.name.Name(components)

    @staticmethod
    def build_llo(
            builder: Union[x509.CertificateBuilder, x509.CertificateSigningRequestBuilder],
            issuer_private_key: PrivateKey,
            issuer_subject: x509.name.Name,
            private_key: PrivateKey,
            certificate_type: CertificateTypes,
            subject: x509.name.Name,
            alternative_names: list = None,
            extra_extensions: list = None,
            not_valid_before: datetime.datetime = None,
            not_valid_after: datetime.datetime = None,
            serial_number: int = None,
            term: int = Constants.DEFAULT_CERTIFICATE_TERM
    ) -> Union[x509.Certificate, x509.CertificateSigningRequest]:
        builder = builder.subject_name(subject)
        key_usage_dictionary = {
            'digital_signature': False,
            'content_commitment': False,
            'key_encipherment': False,
            'data_encipherment': False,
            'key_agreement': False,
            'key_cert_sign': False,
            'crl_sign': False,
            'encipher_only': False,
            'decipher_only': False
        }
        if certificate_type == CertificateTypes.CA_STUBBY:
            key_usage_dictionary['digital_signature'] = True
            key_usage_dictionary['key_cert_sign'] = True
            key_usage_dictionary['crl_sign'] = True
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                True
            )
            builder = builder.add_extension(x509.KeyUsage(**key_usage_dictionary), True)
        elif certificate_type == CertificateTypes.CA_INTERMEDIATE:
            key_usage_dictionary['digital_signature'] = True
            key_usage_dictionary['key_cert_sign'] = True
            key_usage_dictionary['crl_sign'] = True
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                True
            )
            builder = builder.add_extension(x509.KeyUsage(**key_usage_dictionary), True)
        elif certificate_type == CertificateTypes.CLIENT:
            key_usage_dictionary['digital_signature'] = True
            key_usage_dictionary['key_encipherment'] = True
            key_usage_dictionary['data_encipherment'] = True
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                True
            )
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                True
            )
            builder = builder.add_extension(x509.KeyUsage(**key_usage_dictionary), True)
        elif certificate_type == CertificateTypes.SERVER:
            key_usage_dictionary['digital_signature'] = True
            key_usage_dictionary['key_encipherment'] = True
            key_usage_dictionary['data_encipherment'] = True
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                True
            )
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                True
            )
            builder = builder.add_extension(x509.KeyUsage(**key_usage_dictionary), True)
        else:
            raise ValueError(f"Unknown certificate type: {certificate_type}")
        if not_valid_before is None:
            not_valid_before = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.llo.public_key()),
            False
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.llo.public_key()),
            False
        )
        if alternative_names is not None and len(alternative_names) > 0:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(alternative_name) for alternative_name in alternative_names]),
                False
            )
        if extra_extensions is not None and len(extra_extensions) > 0:
            for extension_to_add in extra_extensions:
                builder = builder.add_extension(
                    extension_to_add['extension'],
                    extension_to_add['critical']
                )
        if isinstance(builder, x509.CertificateBuilder):
            builder = builder.issuer_name(issuer_subject)
            builder = builder.public_key(private_key.llo.public_key())
            builder = builder.serial_number(
                serial_number
                if serial_number is not None
                else x509.random_serial_number())
            builder = builder.not_valid_before(not_valid_before)
            builder = builder.not_valid_after(
                not_valid_after
                if not_valid_after is not None
                else not_valid_before + datetime.timedelta(days=term)
            )
        return builder.sign(
            private_key=issuer_private_key.llo,
            algorithm=hashes.SHA256()
        )
