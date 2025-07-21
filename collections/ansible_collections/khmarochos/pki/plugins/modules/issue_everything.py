#!/usr/bin/python

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

DOCUMENTATION = r'''
---
module: issue_everything
short_description: Issue end-entity certificates with all required components (private keys, CSRs, passphrases)
description:
    - Handles the complete certificate issuance workflow for end-entity certificates (server, client, or combined certificates).
    - Generates private keys, creates certificate signing requests, issues certificates from the specified CA, and manages passphrases.
    - Supports all certificate types including SERVER, CLIENT, SERVER_CLIENT, and custom certificates with specific extensions.
    - Provides full Ansible change tracking and integrates with existing PKI infrastructure created by init_pki.
    - Automatically handles certificate chains, Subject Alternative Names (SANs), and advanced certificate extensions.
    - All operations are performed in a single atomic operation with comprehensive error handling.
version_added: "0.0.2"
options:
    pki_ca_cascade:
        description:
            - PKI configuration structure containing the target CA for certificate issuance.
            - Must be the same configuration used with init_pki module to ensure compatibility.
            - Contains CA hierarchy, global parameters, and CA-specific settings needed for certificate generation.
        required: true
        type: dict
        elements: dict
    ca_nickname:
        description:
            - Nickname of the Certificate Authority to use for issuing the certificate.
            - Must match a CA nickname that exists in the PKI cascade configuration.
            - Can reference any CA in the hierarchy (root, intermediate, or nested CAs).
            - The CA must have been initialized with init_pki module before issuing certificates.
        required: true
        type: str
    certificate_parameters:
        description:
            - Complete certificate specification including subject, extensions, key parameters, and validity.
            - Contains all necessary information to generate the certificate, private key, and CSR.
            - Supports inheritance of parameters from the issuing CA configuration.
            - Allows override of global settings for specific certificate requirements.
        required: true
        type: dict
        suboptions:
            nickname:
                description:
                    - Unique identifier for the certificate within the CA.
                    - Used as filename base for all generated files (certificate, key, CSR).
                    - Must be unique within the issuing CA's certificate namespace.
                required: true
                type: str
            certificate_type:
                description:
                    - Certificate usage type that determines the certificate extensions.
                    - SERVER for web servers and TLS services, CLIENT for user authentication.
                    - SERVER_CLIENT for dual-purpose certificates, NONE for custom extensions.
                required: true
                type: str
                choices: ['SERVER', 'CLIENT', 'SERVER_CLIENT', 'NONE']
            certificate_term:
                description:
                    - Certificate validity period in days from the current date.
                    - If not specified, inherits from the issuing CA or global configuration.
                    - "Recommended values: 90 days (high security), 365 days (standard), 1825 days (long-term)."
                required: false
                type: int
            certificate_subject_common_name:
                description:
                    - Common Name (CN) for the certificate subject - the primary identifier.
                    - For server certificates, typically the FQDN of the service.
                    - For client certificates, typically the user's email address or username.
                required: true
                type: str
            certificate_subject_alternative_names:
                description:
                    - List of Subject Alternative Names (DNS names, IP addresses, email addresses).
                    - "Format as DNS:example.com, IP:192.168.1.1, email:user@example.com."
                    - Critical for modern TLS where browsers require SAN matching.
                required: false
                type: list
                elements: str
            certificate_subject_country_name:
                description:
                    - Two-letter ISO country code for the certificate subject.
                    - Inherits from CA configuration if not specified.
                required: false
                type: str
            certificate_subject_state_or_province_name:
                description:
                    - Full state or province name for the certificate subject.
                    - Inherits from CA configuration if not specified.
                required: false
                type: str
            certificate_subject_locality_name:
                description:
                    - City or locality name for the certificate subject.
                    - Inherits from CA configuration if not specified.
                required: false
                type: str
            certificate_subject_organization_name:
                description:
                    - Organization or company name for the certificate subject.
                    - Inherits from CA configuration if not specified.
                required: false
                type: str
            certificate_subject_organizational_unit_name:
                description:
                    - Department or organizational unit for the certificate subject.
                    - Inherits from CA configuration if not specified.
                required: false
                type: str
            certificate_subject_email_address:
                description:
                    - Email address for the certificate subject.
                    - Often used for client certificates and certificate contact information.
                required: false
                type: str
            private_key_encrypted:
                description:
                    - Whether to encrypt the private key with a passphrase.
                    - When true, generates or uses specified passphrase for key encryption.
                    - Recommended for high-security environments and client certificates.
                required: false
                type: bool
                default: false
            private_key_size:
                description:
                    - RSA key size in bits for the certificate's private key.
                    - "Common values: 2048 (standard), 3072 (enhanced), 4096 (high security)."
                    - Larger keys provide more security but impact performance.
                required: false
                type: int
                default: 2048
            private_key_passphrase_random:
                description:
                    - Generate a random passphrase if private key encryption is enabled.
                    - When true, creates a cryptographically secure random passphrase.
                    - Length controlled by private_key_passphrase_length parameter.
                required: false
                type: bool
                default: true
    hide_passphrase_value:
        description:
            - Hide actual passphrase values in Ansible output for security.
            - When true, passphrases are replaced with "[HIDDEN]" in the result.
            - When false, actual passphrase values are included (use with caution).
            - Does not affect the actual passphrase generation or storage, only output display.
        required: false
        type: bool
        default: true
notes:
    - The issuing CA must exist and be properly initialized before using this module.
    - All generated files use the same base filename derived from the certificate nickname.
    - Private keys are created with 600 permissions, certificates with 644 permissions.
    - Certificate chains are automatically generated and include the full trust path to the root CA.
    - The module respects existing certificates and only generates missing components unless forced.
seealso:
    - module: khmarochos.pki.init_pki
    - module: khmarochos.pki.init_dictionary
author:
    - Volodymyr Melnyk (@volodymyr-melnyk)
'''

EXAMPLES = r'''
# Basic web server certificate
- name: Issue certificate for web server
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "intermediate"
    certificate_parameters:
      nickname: "web-server"
      certificate_type: "SERVER"
      certificate_term: 365
      certificate_subject_common_name: "www.example.com"
      certificate_subject_alternative_names:
        - "DNS:www.example.com"
        - "DNS:example.com"
        - "DNS:api.example.com"
        - "IP:192.168.1.100"
      private_key_encrypted: false
      private_key_size: 2048
  register: web_cert

- name: Show certificate location
  debug:
    msg: "Certificate saved to: {{ web_cert.result.certificate.file }}"

# Encrypted client certificate with custom subject
- name: Issue encrypted client certificate
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "client-ca"
    certificate_parameters:
      nickname: "john-doe"
      certificate_type: "CLIENT"
      certificate_term: 90
      certificate_subject_common_name: "john.doe@example.com"
      certificate_subject_email_address: "john.doe@example.com"
      certificate_subject_organizational_unit_name: "Engineering Department"
      private_key_encrypted: true
      private_key_passphrase_random: true
      private_key_size: 2048
    hide_passphrase_value: true
  register: client_cert

- name: Show client certificate details  
  debug:
    msg: |
      Client certificate issued:
      - Certificate: {{ client_cert.result.certificate.file }}
      - Private Key: {{ client_cert.result.private_key.file }}
      - Encrypted: {{ client_cert.result.private_key.encrypted }}

# Server-client dual-purpose certificate
- name: Issue combined server-client certificate
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "intermediate"
    certificate_parameters:
      nickname: "service-account"
      certificate_type: "SERVER_CLIENT"
      certificate_term: 180
      certificate_subject_common_name: "service.internal.com"
      certificate_subject_alternative_names:
        - "DNS:service.internal.com"
        - "DNS:service.example.com"
        - "email:service@example.com"
      private_key_encrypted: false
      private_key_size: 2048
  register: dual_cert

# Kubernetes API server certificate with extensive SANs
- name: Issue certificate for Kubernetes API server
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "kubernetes"
    certificate_parameters:
      nickname: "kube-apiserver"
      certificate_type: "SERVER"
      certificate_term: 365
      certificate_subject_common_name: "kube-apiserver"
      certificate_subject_alternative_names:
        - "DNS:kubernetes"
        - "DNS:kubernetes.default"
        - "DNS:kubernetes.default.svc"
        - "DNS:kubernetes.default.svc.cluster.local"
        - "DNS:api.k8s.example.com"
        - "IP:10.96.0.1"        # Cluster IP
        - "IP:192.168.1.10"     # Master node IP
        - "IP:10.0.0.1"         # Load balancer IP
      private_key_encrypted: false
      private_key_size: 2048
  register: k8s_cert

# Certificate with custom validity period and all subject fields
- name: Issue comprehensive certificate with full subject
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "production"
    certificate_parameters:
      nickname: "enterprise-api"
      certificate_type: "SERVER"
      certificate_term: 30  # Short-lived certificate
      certificate_subject_common_name: "api.enterprise.com"
      certificate_subject_country_name: "US"
      certificate_subject_state_or_province_name: "California"
      certificate_subject_locality_name: "San Francisco"
      certificate_subject_organization_name: "Enterprise Corp"
      certificate_subject_organizational_unit_name: "API Services"
      certificate_subject_email_address: "api-admin@enterprise.com"
      certificate_subject_alternative_names:
        - "DNS:api.enterprise.com"
        - "DNS:api-v1.enterprise.com"
        - "DNS:api-v2.enterprise.com"
        - "IP:203.0.113.10"
      private_key_encrypted: true
      private_key_passphrase_random: true
      private_key_size: 4096
    hide_passphrase_value: true
  register: enterprise_cert

# Bulk certificate issuance with loop
- name: Issue multiple server certificates
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "web-services"
    certificate_parameters:
      nickname: "{{ item.name }}"
      certificate_type: "SERVER"
      certificate_term: 365
      certificate_subject_common_name: "{{ item.fqdn }}"
      certificate_subject_alternative_names:
        - "DNS:{{ item.fqdn }}"
        - "DNS:{{ item.alt_name | default(item.fqdn) }}"
      private_key_encrypted: false
      private_key_size: 2048
  loop:
    - { name: "web01", fqdn: "web01.example.com", alt_name: "www.example.com" }
    - { name: "web02", fqdn: "web02.example.com", alt_name: "app.example.com" }
    - { name: "api-gateway", fqdn: "api.example.com" }
  register: bulk_certs

- name: Display bulk certificate results
  debug:
    msg: |
      Certificate {{ item.item.name }}:
      - File: {{ item.result.certificate.file }}
      - Valid until: {{ item.result.certificate.not_after }}
      - Changed: {{ item.changed }}
  loop: "{{ bulk_certs.results }}"

# Error handling and conditional certificate issuance
- name: Issue certificate with error handling
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "{{ target_ca | default('intermediate') }}"
    certificate_parameters:
      nickname: "{{ cert_name }}"
      certificate_type: "{{ cert_type | default('SERVER') }}"
      certificate_term: "{{ cert_validity | default(365) }}"
      certificate_subject_common_name: "{{ cert_common_name }}"
      certificate_subject_alternative_names: "{{ cert_sans | default([]) }}"
      private_key_encrypted: "{{ cert_encrypt_key | default(false) }}"
      private_key_size: "{{ cert_key_size | default(2048) }}"
  register: conditional_cert
  failed_when: false

- name: Handle certificate issuance failure
  debug:
    msg: "Certificate issuance failed: {{ conditional_cert.msg }}"
  when: conditional_cert.failed

- name: Handle certificate issuance success
  debug:
    msg: |
      Certificate issued successfully:
      - Name: {{ conditional_cert.result.certificate.subject_cn }}
      - File: {{ conditional_cert.result.certificate.file }}
      - Serial: {{ conditional_cert.result.certificate.serial_number }}
  when: not conditional_cert.failed

# Certificate renewal scenario
- name: Renew existing certificate (force regeneration)
  khmarochos.pki.issue_everything:
    pki_ca_cascade: "{{ pki_cascade_configuration }}"
    ca_nickname: "intermediate"
    certificate_parameters:
      nickname: "web-server"
      certificate_type: "SERVER"
      certificate_term: 365
      certificate_subject_common_name: "www.example.com"
      private_key_encrypted: false
      save_forced: true  # Force renewal even if certificate exists
  register: renewed_cert
  tags: [certificate_renewal]

- name: Verify certificate renewal
  debug:
    msg: "Certificate renewed with new expiration: {{ renewed_cert.result.certificate.not_after }}"
  when: renewed_cert.changed
'''

RETURN = r'''
result:
    description: All generated PKI components with detailed properties and file locations
    returned: always
    type: dict
    contains:
        certificate:
            description: Certificate properties including file paths, subject details, validity dates, and extensions
            type: dict
            returned: always
            contains:
                file:
                    description: Full path to the certificate file
                    type: str
                    sample: "/opt/pki/intermediate/certs/CA/web-server.crt"
                chain_file:
                    description: Full path to the certificate chain file (certificate + CA chain)
                    type: str
                    sample: "/opt/pki/intermediate/certs/CA/web-server.chain.crt"
                subject:
                    description: Certificate subject distinguished name
                    type: str
                    sample: "CN=www.example.com,O=Example Corp,C=US"
                subject_cn:
                    description: Common Name from the certificate subject
                    type: str
                    sample: "www.example.com"
                issuer:
                    description: Certificate issuer distinguished name
                    type: str
                    sample: "CN=Intermediate Certificate Authority,O=Example Corp,C=US"
                serial_number:
                    description: Certificate serial number in hexadecimal format
                    type: str
                    sample: "1234567890ABCDEF"
                not_before:
                    description: Certificate validity start date in ISO format
                    type: str
                    sample: "2024-01-01T00:00:00Z"
                not_after:
                    description: Certificate validity end date in ISO format
                    type: str
                    sample: "2025-01-01T00:00:00Z"
                key_usage:
                    description: List of key usage extensions
                    type: list
                    elements: str
                    sample: ["digital_signature", "key_encipherment"]
                extended_key_usage:
                    description: List of extended key usage extensions
                    type: list
                    elements: str
                    sample: ["server_auth", "client_auth"]
                subject_alternative_names:
                    description: List of Subject Alternative Names
                    type: list
                    elements: str
                    sample: ["DNS:www.example.com", "DNS:example.com", "IP:192.168.1.100"]
                certificate_type:
                    description: The type of certificate issued
                    type: str
                    sample: "SERVER"
        certificate_signing_request:
            description: CSR properties and file information
            type: dict
            returned: always
            contains:
                file:
                    description: Full path to the CSR file
                    type: str
                    sample: "/opt/pki/intermediate/csr/CA/web-server.csr"
                subject:
                    description: CSR subject distinguished name
                    type: str
                    sample: "CN=www.example.com,O=Example Corp,C=US"
                public_key_algorithm:
                    description: Public key algorithm used in the CSR
                    type: str
                    sample: "RSA"
                public_key_size:
                    description: Public key size in bits
                    type: int
                    sample: 2048
                extensions:
                    description: List of requested certificate extensions
                    type: list
                    elements: str
                    sample: ["key_usage", "extended_key_usage", "subject_alternative_name"]
        private_key:
            description: Private key properties including encryption status, key size, and file location
            type: dict
            returned: always
            contains:
                file:
                    description: Full path to the private key file
                    type: str
                    sample: "/opt/pki/intermediate/private/CA/web-server.key"
                encrypted:
                    description: Whether the private key is encrypted with a passphrase
                    type: bool
                    sample: false
                algorithm:
                    description: Private key algorithm
                    type: str
                    sample: "RSA"
                key_size:
                    description: Private key size in bits
                    type: int
                    sample: 2048
                file_permissions:
                    description: File permissions for the private key file
                    type: str
                    sample: "600"
        passphrase:
            description: Passphrase information (value may be hidden based on hide_passphrase_value parameter)
            type: dict
            returned: when private_key_encrypted is true
            contains:
                file:
                    description: Full path to the passphrase file
                    type: str
                    sample: "/opt/pki/intermediate/private/CA/web-server.key_passphrase"
                length:
                    description: Length of the passphrase
                    type: int
                    sample: 32
                randomly_generated:
                    description: Whether the passphrase was randomly generated
                    type: bool
                    sample: true
                value:
                    description: Actual passphrase value (may be hidden)
                    type: str
                    sample: "[HIDDEN]"
                file_permissions:
                    description: File permissions for the passphrase file
                    type: str
                    sample: "600"
    sample:
        certificate:
            file: "/opt/pki/intermediate/certs/CA/web-server.crt"
            chain_file: "/opt/pki/intermediate/certs/CA/web-server.chain.crt"
            subject: "CN=www.example.com,O=Example Corp,C=US"
            subject_cn: "www.example.com"
            issuer: "CN=Intermediate Certificate Authority,O=Example Corp,C=US"
            serial_number: "1A2B3C4D5E6F7890"
            not_before: "2024-01-01T00:00:00Z"
            not_after: "2025-01-01T00:00:00Z"
            key_usage: ["digital_signature", "key_encipherment"]
            extended_key_usage: ["server_auth"]
            subject_alternative_names: ["DNS:www.example.com", "DNS:example.com"]
            certificate_type: "SERVER"
        certificate_signing_request:
            file: "/opt/pki/intermediate/csr/CA/web-server.csr"
            subject: "CN=www.example.com,O=Example Corp,C=US"
            public_key_algorithm: "RSA"
            public_key_size: 2048
            extensions: ["key_usage", "extended_key_usage", "subject_alternative_name"]
        private_key:
            file: "/opt/pki/intermediate/private/CA/web-server.key"
            encrypted: false
            algorithm: "RSA"
            key_size: 2048
            file_permissions: "600"
        passphrase: null
changed:
    description: Whether any new certificates or keys were generated
    returned: always
    type: bool
    sample: true
'''

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker \
    import ChangesStack
from ansible_collections.khmarochos.pki.plugins.module_utils.exceptions \
    import PKICascadeError
from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade \
    import PKICascade
from ansible_collections.khmarochos.pki.plugins.module_utils.prepare_parameters \
    import translate_certificate_parameters


ARGUMENT_SPEC = {
    'pki_ca_cascade': {'required': True, 'type': 'dict'},
    'ca_nickname': {'required': True, 'type': 'str'},
    'certificate_parameters': {'required': True, 'type': 'dict'}
}


def main():

    module = AnsibleModule(argument_spec=ARGUMENT_SPEC)

    changes_stack = ChangesStack()

    pki_cascade = None

    try:
        pki_cascade = PKICascade(
            pki_cascade_configuration=module.params['pki_ca_cascade'],
            changes_stack=changes_stack
        )
    except Exception as e:
        module.fail_json(msg=f"Can't traverse the PKI cascade: {e.__str__()}")

    try:
        pki_cascade.setup(load_if_exists=True, save_if_needed=True, save_forced=False)
    except Exception as e:
        module.fail_json(msg=f"Can't set up the PKI cascade: {e.__str__()}")

    pki_ca = None

    try:
        ca_nickname = module.params['ca_nickname']
        pki_ca = pki_cascade.get_ca(nickname=ca_nickname, loose=True)
        if pki_ca is None:
            module.fail_json(msg=f"Can't find the '{ca_nickname}' certificate authority")
    except Exception as e:
        module.fail_json(msg=f"Can't fetch the certificate authority's configuration: {e.__str__()}")

    everything = None

    try:
        certificate_parameters = module.params['certificate_parameters']
        everything = pki_ca.issue(**translate_certificate_parameters(certificate_parameters))
    except Exception as e:
        module.fail_json(msg=f"Can't issue a certificate: {e.__str__()}")

    certificate_properties = everything['certificate'].get_properties(
        builtins_only=True
    ) \
        if everything['certificate'] is not None \
        else None
    certificate_signing_request_properties = everything['certificate_signing_request'].get_properties(
        builtins_only=True
    ) \
        if everything['certificate_signing_request'] is not None \
        else None
    private_key_properties = everything['private_key'].get_properties(
        builtins_only=True
    ) \
        if everything['private_key'] is not None \
        else None
    passphrase_properties = everything['passphrase'].get_properties(
        builtins_only=True,
        hide_value=module.params.get('hide_passphrase_value', True)
    ) \
        if everything['passphrase'] is not None \
        else None

    module.exit_json(
        changed=bool(changes_stack.__len__() > 0),
        result={
            'certificate': certificate_properties,
            'certificate_signing_request': certificate_signing_request_properties,
            'private_key': private_key_properties,
            'passphrase': passphrase_properties
        }
    )

if __name__ == '__main__':
    main()
