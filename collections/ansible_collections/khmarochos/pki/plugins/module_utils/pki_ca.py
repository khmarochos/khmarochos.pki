import os.path
import string
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate import Certificate
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.key import Key
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


# noinspection PyCompatibility
class PKICA(FlexiClass, properties={
    # default parameters for parameters' definitions
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.ON_SET,
        'type': str
    },
    # global parameters
    'nickname': {'mandatory': True},
    'name': {'default': '${nickname} Certificate Authority'},
    'parent_nickname': {'readonly': True},
    'default': {'default': False, 'type': bool},
    'domain': {'mandatory': True},
    'strict': {'default': False, 'type': bool},
    'stubby': {'default': False, 'type': bool},
    # CA key parameters
    'key': {'type': Key},
    'key_llo': {'default': None, 'type': rsa.RSAPrivateKey},
    'key_size': {'default': 4096, 'type': int},
    'key_public_exponent': {'default': 65537, 'type': int},
    'key_encrypted': {'default': False, 'type': bool},
    'key_passphrase': {'default': None, 'type': Passphrase},
    'key_passphrase_value': {'default': None, 'interpolate': FlexiClass.InterpolatorBehaviour.NEVER},
    'key_passphrase_random': {'default': False, 'type': bool},
    'key_passphrase_length': {'default': 32, 'type': int},
    'key_passphrase_character_set': {'default': string.ascii_letters + string.digits + string.punctuation},
    # CA keystore parameters
    'keystore_passphrase': {'default': None, 'type': Passphrase},
    'keystore_passphrase_value': {'default': None, 'interpolate': FlexiClass.InterpolatorBehaviour.NEVER},
    'keystore_passphrase_random': {'default': False, 'type': bool},
    'keystore_passphrase_length': {'type': int, 'default': 32},
    'keystore_passphrase_character_set': {'default': string.ascii_letters + string.digits + string.punctuation},
    # CA certificate parameters
    'certificate_signing_request': {'type': CertificateSigningRequest},
    'certificate_signing_request_llo': {'default': None, 'type': x509.CertificateSigningRequest},
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
    }
}):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def setup(self):
        self.setup_directories()
        self.setup_certificate()

    def setup_directories(self):
        for directory, mode in {
            self.root_directory: 0o755,
            self.private_directory: 0o700,
            self.certificate_signing_requests_directory: 0o755,
            self.certificates_directory: 0o755,
            self.certificate_revocation_lists_directory: 0o755
        }.items():
            if os.path.exists(directory):
                if not os.path.isdir(directory):
                    raise Exception(f"Path '{directory}' exists but is not a directory")
                if not os.stat(directory).st_mode & mode == mode:
                    raise Exception(f"Path '{directory}' exists but has wrong permissions")
            else:
                os.makedirs(directory, mode=mode)

    def setup_certificate(self):
        if self.certificate is None:
            with self._ignore_readonly('certificate'):
                self.certificate = Certificate(
                    file=self.certificate_file,
                    llo=self.certificate_llo,
                    term=self.certificate_term,
                    subject_country=self.certificate_subject_country,
                    subject_state_or_province=self.certificate_subject_state_or_province,
                    subject_locality=self.certificate_subject_locality,
                    subject_organization=self.certificate_subject_organization,
                    subject_organizational_unit=self.certificate_subject_organizational_unit,
                    subject_email_address=self.certificate_subject_email_address,
                    subject_common_name=self.certificate_subject_common_name,
                    key=self.key,
                    key_llo=self.key_llo,
                    key_size=self.key_size,
                    key_public_exponent=self.key_public_exponent,
                    key_encrypted=self.key_encrypted,
                    key_passphrase=self.key_passphrase,
                    key_passphrase_value=self.key_passphrase_value,
                    key_passphrase_random=self.key_passphrase_random,
                    key_passphrase_length=self.key_passphrase_length,
                    key_passphrase_file=self.key_passphrase_file,
                    certificate_signing_request=self.certificate_signing_request,
                    certificate_signing_request_llo=self.certificate_signing_request_llo,
                    certificate_signing_request_file=self.certificate_signing_request_file,
                )
        self.certificate.setup()