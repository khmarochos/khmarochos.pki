import string
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from os import path

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request import CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.key import Key
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


class Certificate(FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
        'type': str
    },
    'llo': {'type': x509.Certificate},
    'file': {'mandatory': True},
    'term': {'type': int, 'default': Constants.DEFAULT_CERTIFICATE_TERM},
    'subject_country': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_state_or_province': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_locality': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_organization': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_organizational_unit': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_email_address': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_common_name': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'key': {'type': Key},
    'key_llo': {'type': rsa.RSAPrivateKey},
    'key_file': {'type': str},
    'key_size': {'type': int, 'default': Constants.DEFAULT_KEY_SIZE},
    'key_public_exponent': {'type': int, 'default': Constants.DEFAULT_KEY_PUBLIC_EXPONENT},
    'key_encrypted': {'type': bool, 'default': Constants.DEFAULT_KEY_ENCRYPTED},
    'key_passphrase': {'type': Passphrase},
    'key_passphrase_value': {},
    'key_passphrase_file': {},
    'key_passphrase_random': {'type': bool},
    'key_passphrase_length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'key_passphrase_character_set': {'type': str, 'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET},
    'certificate_signing_request': {'type': CertificateSigningRequest},
    'certificate_signing_request_llo': {'type': x509.CertificateSigningRequest},
    'certificate_signing_request_file': {'type': str},
}):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def setup(self):
        if self.certificate_signing_request is None:
            with self._ignore_readonly('certificate_signing_request'):
                self.certificate_signing_request = CertificateSigningRequest(
                    file=self.certificate_signing_request_file,
                    llo=self.certificate_signing_request_llo,
                    subject_country=self.subject_country,
                    subject_state_or_province=self.subject_state_or_province,
                    subject_locality=self.subject_locality,
                    subject_organization=self.subject_organization,
                    subject_organizational_unit=self.subject_organizational_unit,
                    subject_email_address=self.subject_email_address,
                    subject_common_name=self.subject_common_name,
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
                )
