import string
import q
import enum
import datetime
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from os import path

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
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
    'type': {'type': CertificateTypes, 'mandatory': True},
    'term': {'type': int, 'default': Constants.DEFAULT_CERTIFICATE_TERM},
    'ca': {'type': 'ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade.PKICA'},
    'subject_country': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_state_or_province': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_locality': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_organization': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_organizational_unit': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_email_address': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject_common_name': {'mandatory_unless_any': ['certificate_signing_request', 'certificate']},
    'subject': {'type': x509.name.Name},
    'attributes': {'type': list},
    'key': {'type': Key},
    'key_llo': {'type': rsa.RSAPrivateKey},
    'key_file': {'mandatory_unless_any': ['key', 'certificate_signing_request']},
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

        property_bindings = {
            'file': 'certificate_signing_request_file',
            'llo': 'certificate_signing_request_llo',
            'type': 'type',
            'subject_country': 'subject_country',
            'subject_state_or_province': 'subject_state_or_province',
            'subject_locality': 'subject_locality',
            'subject_organization': 'subject_organization',
            'subject_organizational_unit': 'subject_organizational_unit',
            'subject_email_address': 'subject_email_address',
            'subject_common_name': 'subject_common_name',
            'subject': 'subject',
            'attributes': 'attributes',
            'key': 'key',
            'key_llo': 'key_llo',
            'key_file': 'key_file',
            'key_size': 'key_size',
            'key_public_exponent': 'key_public_exponent',
            'key_encrypted': 'key_encrypted',
            'key_passphrase': 'key_passphrase',
            'key_passphrase_value': 'key_passphrase_value',
            'key_passphrase_random': 'key_passphrase_random',
            'key_passphrase_length': 'key_passphrase_length',
            'key_passphrase_file': 'key_passphrase_file'
        }

        if self.certificate_signing_request is None:
            with self.ignore_readonly('certificate_signing_request'):
                self.certificate_signing_request = CertificateSigningRequest(** self._bind_arguments(property_bindings))

        self._bind_properties([{
            'object': self.certificate_signing_request,
            'properties': property_bindings
        }])


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
            self.llo = x509.load_pem_x509_certificate(f.read())

    def make_llo(self):
        with ((self.ignore_readonly('llo'))):
            self.llo = x509.CertificateBuilder() \
                .subject_name(self.subject) \
                .issuer_name(self.ca.certificate.subject if self.ca is not None else self.subject) \
                .public_key(self.key.llo.public_key()) \
                .serial_number(x509.random_serial_number()) \
                .not_valid_before(datetime.datetime.utcnow()) \
                .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=self.term)) \
                .sign(
                    private_key=self.ca.key.llo if self.ca is not None else self.key.llo,
                    algorithm=hashes.SHA256()
                )

    def save_llo(self):
        with open(self.file, 'wb') as f:
            f.write(self.llo.public_bytes(encoding=serialization.Encoding.PEM))
