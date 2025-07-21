#!/usr/bin/env python3
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

"""
PKI State Dump Script

This script traverses a PKI directory structure to discover Certificate Authorities (CAs)
and their certificates, private keys, and issued certificates. It generates a comprehensive
JSON dump of the entire PKI state including hierarchical CA structures.

Expected directory structure:
{global_root_directory}/{ca_nickname}/
├── private/CA/{ca_nickname}.key          # CA private key
├── private/CA/{ca_nickname}.key_passphrase  # CA private key passphrase (if encrypted)
├── certs/CA/{ca_nickname}.crt            # CA certificate
├── csr/CA/{ca_nickname}.csr              # CA certificate signing request
└── {issued_cert_dirs}                    # Issued certificates
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

# Add the collection's path to the Python path
script_dir = Path(__file__).parent
collection_base_path = script_dir.parent / "collections"
sys.path.insert(0, str(collection_base_path))

# Import cryptography modules
from cryptography import x509
from cryptography.hazmat.primitives import hashes

try:
    from ansible_collections.khmarochos.pki.plugins.module_utils.pki_ca import PKICA
    from ansible_collections.khmarochos.pki.plugins.module_utils.certificate import Certificate
    from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
    from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import CertificateSigningRequest
    from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase
    from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
    from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangesStack
except ImportError as e:
    print(f"Error importing PKI modules: {e}")
    print(f"Make sure the script is run from the correct directory")
    sys.exit(1)


class PKIStateDumper:
    """Main class for dumping PKI state to JSON"""
    
    def __init__(self, global_root_directory: str):
        self.global_root_directory = Path(global_root_directory)
        self.changes_stack = ChangesStack()
        self.logger = logging.getLogger(__name__)
        
    def discover_cas(self) -> List[str]:
        """Discover all CA directories in the global root directory"""
        cas = []
        if not self.global_root_directory.exists():
            self.logger.warning(f"Global root directory {self.global_root_directory} does not exist")
            return cas
            
        for item in self.global_root_directory.iterdir():
            if item.is_dir():
                ca_cert_file = item / "certs" / "CA" / f"{item.name}.crt"
                ca_key_file = item / "private" / "CA" / f"{item.name}.key"
                
                if ca_cert_file.exists() and ca_key_file.exists():
                    cas.append(item.name)
                    self.logger.info(f"Found CA: {item.name}")
                    
        return cas
    
    def load_ca(self, ca_nickname: str) -> Optional[PKICA]:
        """Load a CA object from the filesystem"""
        try:
            ca = PKICA(
                nickname=ca_nickname,
                global_root_directory=str(self.global_root_directory),
                domain="example.com",  # This will be overridden by actual cert data
                certificate_subject_country_name="XX",
                certificate_subject_state_or_province_name="Unknown",
                certificate_subject_locality_name="Unknown",
                certificate_subject_organization_name="Unknown",
                certificate_subject_organizational_unit_name="Unknown",
                certificate_subject_email_address="unknown@example.com",
                changes_stack=self.changes_stack
            )
            
            # Load existing certificate and private key
            if Path(ca.certificate_file).exists():
                with ca.ignore_readonly('certificate'):
                    ca.certificate = Certificate(
                        nickname=ca_nickname,
                        file=ca.certificate_file,
                        changes_stack=self.changes_stack
                    )
                    ca.certificate.load()
                
            if Path(ca.private_key_file).exists():
                # Check if passphrase file exists
                passphrase = None
                if Path(ca.private_key_passphrase_file).exists():
                    passphrase = Passphrase(
                        file=ca.private_key_passphrase_file,
                        changes_stack=self.changes_stack
                    )
                    passphrase.load()
                
                with ca.ignore_readonly('private_key'):
                    ca.private_key = PrivateKey(
                        nickname=ca_nickname,
                        file=ca.private_key_file,
                        encrypted=passphrase is not None,
                        passphrase=passphrase,
                        changes_stack=self.changes_stack
                    )
                    ca.private_key.load()
                
            # Load CSR if it exists
            if Path(ca.certificate_signing_request_file).exists():
                with ca.ignore_readonly('certificate_signing_request'):
                    ca.certificate_signing_request = CertificateSigningRequest(
                        nickname=ca_nickname,
                        file=ca.certificate_signing_request_file,
                        changes_stack=self.changes_stack
                    )
                    ca.certificate_signing_request.load()
                
            return ca
            
        except Exception as e:
            self.logger.error(f"Failed to load CA {ca_nickname}: {e}")
            return None
    
    def should_skip_chain_file(self, chain_file: Path, cert_dir: Path) -> bool:
        """Check if a chain file should be skipped because it duplicates a standalone certificate"""
        # Extract base name (e.g., "example.chain.crt" -> "example")
        if not chain_file.name.endswith('.chain.crt'):
            return False
            
        base_name = chain_file.name.replace('.chain.crt', '')
        standalone_file = cert_dir / f"{base_name}.crt"
        
        if not standalone_file.exists():
            return False
            
        try:
            # Load the first certificate from the chain file
            with open(chain_file, 'r') as f:
                chain_content = f.read()
            
            # Extract the first certificate from the chain (between first BEGIN and first END)
            begin_marker = "-----BEGIN CERTIFICATE-----"
            end_marker = "-----END CERTIFICATE-----"
            
            begin_pos = chain_content.find(begin_marker)
            if begin_pos == -1:
                return False
                
            end_pos = chain_content.find(end_marker, begin_pos)
            if end_pos == -1:
                return False
                
            first_cert_pem = chain_content[begin_pos:end_pos + len(end_marker)]
            
            # Load the standalone certificate
            with open(standalone_file, 'r') as f:
                standalone_content = f.read().strip()
            
            # Compare the certificates (normalize whitespace)
            first_cert_normalized = '\n'.join(line.strip() for line in first_cert_pem.split('\n') if line.strip())
            standalone_normalized = '\n'.join(line.strip() for line in standalone_content.split('\n') if line.strip())
            
            if first_cert_normalized == standalone_normalized:
                self.logger.debug(f"Skipping chain file {chain_file.name} - duplicates {standalone_file.name}")
                return True
                
        except Exception as e:
            self.logger.warning(f"Failed to compare {chain_file.name} with {standalone_file.name}: {e}")
            
        return False

    def discover_issued_certificates(self, ca: PKICA) -> Dict[str, Dict[str, Any]]:
        """Discover all certificates issued by a CA"""
        issued_certs = {}
        ca_root = Path(ca.root_directory)
        
        # Look for certificates in various directories
        for cert_dir in ["certs", "private", "csr"]:
            cert_path = ca_root / cert_dir
            if cert_path.exists():
                for cert_file in cert_path.glob("*.crt"):
                    # Skip the CA's own certificate
                    if cert_file.name == f"{ca.nickname}.crt":
                        continue
                    
                    # Skip chain files that duplicate standalone certificates
                    if self.should_skip_chain_file(cert_file, cert_path):
                        continue
                        
                    cert_nickname = cert_file.stem
                    if cert_nickname not in issued_certs:
                        issued_certs[cert_nickname] = {}
                        
                    try:
                        # Load certificate
                        cert = Certificate(
                            nickname=cert_nickname,
                            file=str(cert_file),
                            changes_stack=self.changes_stack
                        )
                        cert.load()
                        issued_certs[cert_nickname]['certificate'] = self.serialize_certificate(cert)
                        
                        # Determine certificate type
                        cert_type = self.determine_certificate_type(cert)
                        issued_certs[cert_nickname]['type'] = cert_type
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to load certificate {cert_file}: {e}")
                        
                # Look for corresponding private keys
                for key_file in cert_path.glob("*.key"):
                    if key_file.name == f"{ca.nickname}.key":
                        continue
                        
                    key_nickname = key_file.stem
                    if key_nickname not in issued_certs:
                        issued_certs[key_nickname] = {}
                        
                    try:
                        # Check for passphrase
                        passphrase_file = key_file.with_suffix('.key_passphrase')
                        passphrase = None
                        if passphrase_file.exists():
                            passphrase = Passphrase(
                                file=str(passphrase_file),
                                changes_stack=self.changes_stack
                            )
                            passphrase.load()
                            
                        # Load private key
                        private_key = PrivateKey(
                            nickname=key_nickname,
                            file=str(key_file),
                            encrypted=passphrase is not None,
                            passphrase=passphrase,
                            changes_stack=self.changes_stack
                        )
                        private_key.load()
                        issued_certs[key_nickname]['private_key'] = self.serialize_private_key(private_key)
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to load private key {key_file}: {e}")
                        
                # Look for CSRs
                for csr_file in cert_path.glob("*.csr"):
                    if csr_file.name == f"{ca.nickname}.csr":
                        continue
                        
                    csr_nickname = csr_file.stem
                    if csr_nickname not in issued_certs:
                        issued_certs[csr_nickname] = {}
                        
                    try:
                        csr = CertificateSigningRequest(
                            nickname=csr_nickname,
                            file=str(csr_file),
                            changes_stack=self.changes_stack
                        )
                        csr.load()
                        issued_certs[csr_nickname]['certificate_signing_request'] = self.serialize_csr(csr)
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to load CSR {csr_file}: {e}")
                        
        return issued_certs
    
    def determine_certificate_type(self, cert: Certificate) -> str:
        """Determine the type of certificate based on its extensions"""
        try:
            cert_obj = cert.llo
            
            # Check for CA certificate
            try:
                basic_constraints = cert_obj.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                ).value
                if basic_constraints.ca:
                    return "ca"
            except x509.ExtensionNotFound:
                pass
                
            # Check for key usage extensions
            try:
                key_usage = cert_obj.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.KEY_USAGE
                ).value
                
                if key_usage.digital_signature and key_usage.key_encipherment:
                    return "server_client"
                elif key_usage.digital_signature:
                    return "client"
                elif key_usage.key_encipherment:
                    return "server"
            except x509.ExtensionNotFound:
                pass
                
            # Check for extended key usage
            try:
                ext_key_usage = cert_obj.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
                ).value
                
                has_server = x509.oid.ExtendedKeyUsageOID.SERVER_AUTH in ext_key_usage
                has_client = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH in ext_key_usage
                
                if has_server and has_client:
                    return "server_client"
                elif has_server:
                    return "server"
                elif has_client:
                    return "client"
            except x509.ExtensionNotFound:
                pass
                
            return "unknown"
            
        except Exception as e:
            self.logger.warning(f"Failed to determine certificate type: {e}")
            return "unknown"
    
    def serialize_certificate(self, cert: Certificate) -> Dict[str, Any]:
        """Serialize a Certificate object to a dictionary with enhanced details"""
        try:
            cert_obj = cert.llo
            result = {
                'nickname': cert.nickname,
                'file': cert.file,
                'subject': str(cert_obj.subject),
                'issuer': str(cert_obj.issuer),
                'serial_number': str(cert_obj.serial_number),
                'not_valid_before': cert_obj.not_valid_before.isoformat(),
                'not_valid_after': cert_obj.not_valid_after.isoformat(),
                'signature_algorithm': cert_obj.signature_algorithm_oid._name,
                'public_key_size': cert_obj.public_key().key_size,
                'fingerprint_sha256': cert_obj.fingerprint(hashes.SHA256()).hex(),
            }
            
            # Add Subject Alternative Names
            try:
                san_extension = cert_obj.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value
                sans = []
                for name in san_extension:
                    if isinstance(name, x509.DNSName):
                        sans.append(f"DNS:{name.value}")
                    elif isinstance(name, x509.IPAddress):
                        sans.append(f"IP:{name.value}")
                    elif isinstance(name, x509.RFC822Name):
                        sans.append(f"email:{name.value}")
                    elif isinstance(name, x509.UniformResourceIdentifier):
                        sans.append(f"URI:{name.value}")
                    else:
                        sans.append(f"other:{str(name)}")
                result['subject_alternative_names'] = sans
            except x509.ExtensionNotFound:
                result['subject_alternative_names'] = []
            
            # Add Key Usage
            try:
                key_usage = cert_obj.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.KEY_USAGE
                ).value
                usage_list = []
                if key_usage.digital_signature:
                    usage_list.append('digital_signature')
                if key_usage.key_encipherment:
                    usage_list.append('key_encipherment')
                if key_usage.data_encipherment:
                    usage_list.append('data_encipherment')
                if key_usage.key_agreement:
                    usage_list.append('key_agreement')
                if key_usage.key_cert_sign:
                    usage_list.append('key_cert_sign')
                if key_usage.crl_sign:
                    usage_list.append('crl_sign')
                if hasattr(key_usage, 'content_commitment') and key_usage.content_commitment:
                    usage_list.append('content_commitment')
                result['key_usage'] = usage_list
            except x509.ExtensionNotFound:
                result['key_usage'] = []
            
            # Add Extended Key Usage
            try:
                ext_key_usage = cert_obj.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
                ).value
                ext_usage_list = []
                for usage in ext_key_usage:
                    if usage == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                        ext_usage_list.append('server_auth')
                    elif usage == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                        ext_usage_list.append('client_auth')
                    elif usage == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                        ext_usage_list.append('code_signing')
                    elif usage == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                        ext_usage_list.append('email_protection')
                    elif usage == x509.oid.ExtendedKeyUsageOID.TIME_STAMPING:
                        ext_usage_list.append('time_stamping')
                    elif usage == x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING:
                        ext_usage_list.append('ocsp_signing')
                    else:
                        ext_usage_list.append(str(usage))
                result['extended_key_usage'] = ext_usage_list
            except x509.ExtensionNotFound:
                result['extended_key_usage'] = []
            
            # Add Basic Constraints
            try:
                basic_constraints = cert_obj.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                ).value
                result['basic_constraints'] = {
                    'ca': basic_constraints.ca,
                    'path_length': basic_constraints.path_length
                }
            except x509.ExtensionNotFound:
                result['basic_constraints'] = {'ca': False, 'path_length': None}
            
            # Add Authority Key Identifier
            try:
                auth_key_id = cert_obj.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
                ).value
                result['authority_key_identifier'] = auth_key_id.key_identifier.hex() if auth_key_id.key_identifier else None
            except x509.ExtensionNotFound:
                result['authority_key_identifier'] = None
            
            # Add Subject Key Identifier
            try:
                subj_key_id = cert_obj.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
                ).value
                result['subject_key_identifier'] = subj_key_id.digest.hex()
            except x509.ExtensionNotFound:
                result['subject_key_identifier'] = None
            
            # Add certificate chain validation information
            subject_str = str(cert_obj.subject)
            issuer_str = str(cert_obj.issuer)
            result['is_self_signed'] = subject_str == issuer_str
            
            # Check if this certificate is likely a root CA
            if result['is_self_signed'] and result['basic_constraints']['ca']:
                result['cert_type'] = 'root_ca'
            elif result['basic_constraints']['ca']:
                result['cert_type'] = 'intermediate_ca'
            else:
                result['cert_type'] = 'end_entity'
            
            # Add certificate validation status
            try:
                now = datetime.now().replace(tzinfo=cert_obj.not_valid_before.tzinfo)
                if now < cert_obj.not_valid_before:
                    result['validity_status'] = 'not_yet_valid'
                elif now > cert_obj.not_valid_after:
                    result['validity_status'] = 'expired'
                else:
                    result['validity_status'] = 'valid'
                    
                # Calculate days until expiry
                days_until_expiry = (cert_obj.not_valid_after - now).days
                result['days_until_expiry'] = days_until_expiry
                
            except Exception as validity_error:
                self.logger.debug(f"Failed to check certificate validity: {validity_error}")
                result['validity_status'] = 'unknown'
                result['days_until_expiry'] = None
            
            # Add certificate modulus (for RSA certificates)
            try:
                public_key = cert_obj.public_key()
                if hasattr(public_key, 'public_numbers'):
                    # RSA public key
                    result['public_modulus'] = str(public_key.public_numbers().n)
            except Exception as modulus_error:
                self.logger.debug(f"Failed to get certificate modulus: {modulus_error}")
            
            # Add file information
            try:
                file_path = Path(cert.file)
                if file_path.exists():
                    stat = file_path.stat()
                    result['file_size'] = stat.st_size
                    result['file_permissions'] = oct(stat.st_mode)[-3:]
                    result['last_modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            except Exception as file_error:
                self.logger.debug(f"Failed to get certificate file information: {file_error}")
            
            return result
        except Exception as e:
            self.logger.warning(f"Failed to serialize certificate: {e}")
            return {'nickname': cert.nickname, 'file': cert.file, 'error': str(e)}
    
    def serialize_private_key(self, private_key: PrivateKey) -> Dict[str, Any]:
        """Serialize a PrivateKey object to a dictionary with enhanced details"""
        try:
            result = {
                'nickname': private_key.nickname,
                'file': private_key.file,
                'size': private_key.size,
                'public_exponent': private_key.public_exponent,
                'encrypted': private_key.encrypted,
                'public_modulus': str(private_key.public_modulus),
            }
            
            # Add key type information
            try:
                key_obj = private_key.llo
                if hasattr(key_obj, 'key_size'):
                    result['key_type'] = 'RSA'
                    result['key_strength'] = key_obj.key_size
                    
                    # Add RSA-specific information
                    public_key = key_obj.public_key()
                    result['public_key_numbers'] = {
                        'e': public_key.public_numbers().e,
                        'n': str(public_key.public_numbers().n)
                    }
                    
                elif hasattr(key_obj, 'curve'):
                    result['key_type'] = 'EC'
                    result['curve'] = key_obj.curve.name
                    result['key_strength'] = key_obj.curve.key_size
                else:
                    result['key_type'] = 'Unknown'
                    result['key_strength'] = getattr(key_obj, 'key_size', 0)
            except Exception as key_error:
                self.logger.debug(f"Failed to get detailed key information: {key_error}")
                result['key_type'] = 'Unknown'
                result['key_strength'] = private_key.size
            
            # Check for passphrase file existence
            passphrase_file = private_key.file + '_passphrase'
            result['has_passphrase_file'] = Path(passphrase_file).exists()
            
            # Add file permissions and timestamps
            try:
                file_path = Path(private_key.file)
                if file_path.exists():
                    stat = file_path.stat()
                    result['file_permissions'] = oct(stat.st_mode)[-3:]
                    result['file_size'] = stat.st_size
                    result['last_modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            except Exception as file_error:
                self.logger.debug(f"Failed to get file information: {file_error}")
            
            return result
        except Exception as e:
            self.logger.warning(f"Failed to serialize private key: {e}")
            return {'nickname': private_key.nickname, 'file': private_key.file, 'error': str(e)}
    
    def serialize_csr(self, csr: CertificateSigningRequest) -> Dict[str, Any]:
        """Serialize a CertificateSigningRequest object to a dictionary with enhanced details"""
        try:
            csr_obj = csr.llo
            result = {
                'nickname': csr.nickname,
                'file': csr.file,
                'subject': str(csr_obj.subject),
                'signature_algorithm': csr_obj.signature_algorithm_oid._name,
                'public_key_size': csr_obj.public_key().key_size,
            }
            
            # Add Subject Alternative Names from CSR
            try:
                for extension in csr_obj.extensions:
                    if extension.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                        sans = []
                        for name in extension.value:
                            if isinstance(name, x509.DNSName):
                                sans.append(f"DNS:{name.value}")
                            elif isinstance(name, x509.IPAddress):
                                sans.append(f"IP:{name.value}")
                            elif isinstance(name, x509.RFC822Name):
                                sans.append(f"email:{name.value}")
                            elif isinstance(name, x509.UniformResourceIdentifier):
                                sans.append(f"URI:{name.value}")
                            else:
                                sans.append(f"other:{str(name)}")
                        result['subject_alternative_names'] = sans
                        break
                else:
                    result['subject_alternative_names'] = []
            except Exception as san_error:
                self.logger.debug(f"Failed to parse SANs from CSR: {san_error}")
                result['subject_alternative_names'] = []
            
            # Add key usage extensions from CSR
            try:
                for extension in csr_obj.extensions:
                    if extension.oid == x509.oid.ExtensionOID.KEY_USAGE:
                        key_usage = extension.value
                        usage_list = []
                        if key_usage.digital_signature:
                            usage_list.append('digital_signature')
                        if key_usage.key_encipherment:
                            usage_list.append('key_encipherment')
                        if key_usage.data_encipherment:
                            usage_list.append('data_encipherment')
                        if key_usage.key_agreement:
                            usage_list.append('key_agreement')
                        if key_usage.key_cert_sign:
                            usage_list.append('key_cert_sign')
                        if key_usage.crl_sign:
                            usage_list.append('crl_sign')
                        if hasattr(key_usage, 'content_commitment') and key_usage.content_commitment:
                            usage_list.append('content_commitment')
                        result['key_usage'] = usage_list
                        break
                else:
                    result['key_usage'] = []
            except Exception as ku_error:
                self.logger.debug(f"Failed to parse key usage from CSR: {ku_error}")
                result['key_usage'] = []
            
            # Add extended key usage from CSR
            try:
                for extension in csr_obj.extensions:
                    if extension.oid == x509.oid.ExtensionOID.EXTENDED_KEY_USAGE:
                        ext_key_usage = extension.value
                        ext_usage_list = []
                        for usage in ext_key_usage:
                            if usage == x509.oid.ExtendedKeyUsageOID.SERVER_AUTH:
                                ext_usage_list.append('server_auth')
                            elif usage == x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH:
                                ext_usage_list.append('client_auth')
                            elif usage == x509.oid.ExtendedKeyUsageOID.CODE_SIGNING:
                                ext_usage_list.append('code_signing')
                            elif usage == x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION:
                                ext_usage_list.append('email_protection')
                            elif usage == x509.oid.ExtendedKeyUsageOID.TIME_STAMPING:
                                ext_usage_list.append('time_stamping')
                            elif usage == x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING:
                                ext_usage_list.append('ocsp_signing')
                            else:
                                ext_usage_list.append(str(usage))
                        result['extended_key_usage'] = ext_usage_list
                        break
                else:
                    result['extended_key_usage'] = []
            except Exception as eku_error:
                self.logger.debug(f"Failed to parse extended key usage from CSR: {eku_error}")
                result['extended_key_usage'] = []
            
            # Add public key details
            try:
                public_key = csr_obj.public_key()
                result['public_key_type'] = type(public_key).__name__.replace('PublicKey', '')
                
                if hasattr(public_key, 'public_numbers'):
                    # RSA key
                    result['public_key_details'] = {
                        'e': public_key.public_numbers().e,
                        'n_bits': public_key.key_size
                    }
                elif hasattr(public_key, 'curve'):
                    # EC key
                    result['public_key_details'] = {
                        'curve': public_key.curve.name,
                        'key_size': public_key.curve.key_size
                    }
            except Exception as pk_error:
                self.logger.debug(f"Failed to get public key details from CSR: {pk_error}")
            
            # Add file information
            try:
                file_path = Path(csr.file)
                if file_path.exists():
                    stat = file_path.stat()
                    result['file_size'] = stat.st_size
                    result['last_modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            except Exception as file_error:
                self.logger.debug(f"Failed to get CSR file information: {file_error}")
            
            return result
        except Exception as e:
            self.logger.warning(f"Failed to serialize CSR: {e}")
            return {'nickname': csr.nickname, 'file': csr.file, 'error': str(e)}
    
    def build_ca_hierarchy(self, cas: List[str]) -> Dict[str, Any]:
        """Build a hierarchical structure of CAs and their relationships"""
        ca_objects = {}
        
        # Load all CAs first
        for ca_nickname in cas:
            ca = self.load_ca(ca_nickname)
            if ca:
                ca_objects[ca_nickname] = ca
                
        # Create a mapping of subject to CA nickname for parent lookups
        subject_to_nickname = {}
        for ca_nickname, ca in ca_objects.items():
            if ca.certificate and ca.certificate.llo:
                subject_str = str(ca.certificate.llo.subject)
                subject_to_nickname[subject_str] = ca_nickname
                
        # Build CA data objects
        ca_data_objects = {}
        for ca_nickname, ca in ca_objects.items():
            ca_data_objects[ca_nickname] = {
                'own_certificate': self.serialize_certificate(ca.certificate) if ca.certificate else None,
                'own_private_key': self.serialize_private_key(ca.private_key) if ca.private_key else None,
                'own_certificate_signing_request': self.serialize_csr(ca.certificate_signing_request) if ca.certificate_signing_request else None,
                'issued_certificates': self.discover_issued_certificates(ca),
                'authorities': {}
            }
        
        # Determine hierarchy by examining issuer relationships
        root_cas = set(ca_objects.keys())  # Start with all CAs as potential roots
        parent_child_map = {}  # parent_nickname -> [child_nicknames]
        
        for ca_nickname, ca in ca_objects.items():
            if ca.certificate and ca.certificate.llo:
                subject_str = str(ca.certificate.llo.subject)
                issuer_str = str(ca.certificate.llo.issuer)
                
                # If subject != issuer, this CA was issued by another CA
                if subject_str != issuer_str:
                    # Find the parent CA by matching issuer to subject
                    parent_nickname = subject_to_nickname.get(issuer_str)
                    if parent_nickname and parent_nickname in ca_objects:
                        # This CA has a parent, so it's not a root CA
                        root_cas.discard(ca_nickname)
                        
                        # Add to parent-child mapping
                        if parent_nickname not in parent_child_map:
                            parent_child_map[parent_nickname] = []
                        parent_child_map[parent_nickname].append(ca_nickname)
                        
                        self.logger.debug(f"Found hierarchy: {parent_nickname} -> {ca_nickname}")
                    else:
                        self.logger.warning(f"CA {ca_nickname} has external issuer: {issuer_str}")
                else:
                    self.logger.debug(f"CA {ca_nickname} is self-signed (root CA)")
        
        # Recursively build the hierarchy starting from root CAs
        def build_subtree(ca_nickname: str) -> Dict[str, Any]:
            ca_data = ca_data_objects[ca_nickname].copy()
            
            # Add child CAs to authorities
            children = parent_child_map.get(ca_nickname, [])
            for child_nickname in children:
                ca_data['authorities'][child_nickname] = build_subtree(child_nickname)
                
            return ca_data
        
        # Build the final hierarchy starting from root CAs
        authorities = {}
        for root_ca in sorted(root_cas):  # Sort for consistent output
            authorities[root_ca] = build_subtree(root_ca)
            
        self.logger.info(f"Built CA hierarchy with {len(root_cas)} root CAs: {sorted(root_cas)}")
        if parent_child_map:
            for parent, children in parent_child_map.items():
                self.logger.info(f"  {parent} issues: {children}")
        
        return {'authorities': authorities}
    
    def dump_state(self, output_file: Optional[str] = None) -> Dict[str, Any]:
        """Main method to dump the entire PKI state"""
        self.logger.info(f"Starting PKI state dump from {self.global_root_directory}")
        
        # Discover all CAs
        cas = self.discover_cas()
        self.logger.info(f"Found {len(cas)} Certificate Authorities: {cas}")
        
        # Build the complete state
        state = self.build_ca_hierarchy(cas)
        
        # Output the result
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(state, f, indent=2)
            self.logger.info(f"State dumped to {output_file}")
        else:
            print(json.dumps(state, indent=2))
            
        return state


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Dump PKI state to JSON")
    parser.add_argument("global_root_directory", 
                       help="Path to the global PKI root directory")
    parser.add_argument("-o", "--output", 
                       help="Output file path (default: stdout)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create dumper and run
    dumper = PKIStateDumper(args.global_root_directory)
    try:
        dumper.dump_state(args.output)
    except Exception as e:
        logging.error(f"Failed to dump PKI state: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()