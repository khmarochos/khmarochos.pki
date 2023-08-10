import os.path
import re
import q

from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.key import Key
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


# noinspection PyCompatibility
class PKICA(FlexiClass, properties={
    # default parameters for parameters' definitions
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.ON_GET,
        'type': str
    },
    # global parameters
    'nickname': {'mandatory': True},
    'name': {'default': 'CA ${nickname}'},
    'parent_nickname': {'readonly': True},
    'default': {'default': False, 'type': bool},
    'domain': {'mandatory': True},
    'strict': {'default': False, 'type': bool},
    'stubby': {'default': False, 'type': bool},
    # CA key parameters
    'key': {'type': Key},
    'key_size': {'default': 4096, 'type': int},
    'key_public_exponent': {'default': 65537, 'type': int},
    'key_encrypted': {'default': False, 'type': bool},
    'key_passphrase': {'default': None, 'type': Passphrase},
    'key_passphrase_value': {'default': None},
    'key_passphrase_random': {'default': False, 'type': bool},
    'key_passphrase_length': {'default': 32, 'type': int},
    'keystore_passphrase': {'default': None},
    'keystore_passphrase_random': {'default': False, 'type': bool},
    'keystore_passphrase_length': {'default': 32, 'type': int},
    # CA certificate parameters
    'certificate_term': {'default': 3650, 'type': int},
    'certificate_subject_country': {'mandatory': True},
    'certificate_subject_state_or_province': {'mandatory': True},
    'certificate_subject_locality': {'mandatory': True},
    'certificate_subject_organization': {'mandatory': True},
    'certificate_subject_organizational_unit': {'mandatory': True},
    'certificate_subject_email_address': {'mandatory': True},
    'certificate_subject_common_name': {
        'default':
            "CN=${name}/" +
            "OU=${certificate_subject_organizational_unit}/" +
            "O=${certificate_subject_organization}/" +
            "L=${certificate_subject_locality}/" +
            "ST=${certificate_subject_state_or_province}/" +
            "C=${certificate_subject_country}"
    },
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

        if self.key is None:
            with self._ignore_readonly('key'):
                # noInspection PyAttributeOutsideInit
                self.key = Key(
                    file=self.key_file,
                    size=self.key_size,
                    public_exponent=self.key_public_exponent,
                    encrypted=self.key_encrypted,
                    passphrase=self.key_passphrase,
                    passphrase_file=self.key_passphrase_file,
                    passphrase_value=self.key_passphrase_value,
                    passphrase_random=self.key_passphrase_random,
                    passphrase_length=self.key_passphrase_length
                )
        self.setup_key()

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

    def setup_key(self):
        self.key.setup()
