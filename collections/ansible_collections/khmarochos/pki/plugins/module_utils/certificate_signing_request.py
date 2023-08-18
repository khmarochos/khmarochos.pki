from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from os import path
import string
import q

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.key import Key
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


class CertificateSigningRequest(FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
        'type': str
    },
    'llo': {'type': x509.CertificateSigningRequest},
    'file': {'mandatory': True},
    'subject_country': {'mandatory': True},
    'subject_state_or_province': {'mandatory': True},
    'subject_locality': {'mandatory': True},
    'subject_organization': {'mandatory': True},
    'subject_organizational_unit': {'mandatory': True},
    'subject_email_address': {'mandatory': True},
    'subject_common_name': {'mandatory': True},
    'key': {'type': Key},
    'key_llo': {'type': rsa.RSAPrivateKey},
    'key_file': {'mandatory_unless': 'key'},
    'key_size': {'type': int, 'default': Constants.DEFAULT_KEY_SIZE},
    'key_public_exponent': {'type': int, 'default': Constants.DEFAULT_KEY_PUBLIC_EXPONENT},
    'key_encrypted': {'type': bool, 'default': Constants.DEFAULT_KEY_ENCRYPTED},
    'key_passphrase': {'type': Passphrase},
    'key_passphrase_value': {},
    'key_passphrase_file': {},
    'key_passphrase_random': {'type': bool, 'default': Constants.DEFAULT_PASSPHRASE_RANDOM},
    'key_passphrase_length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'key_passphrase_character_set': {'type': str, 'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET},
}):

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        property_bindings = {
            'llo': 'key_llo',
            'file': 'key_file',
            'size': 'key_size',
            'public_exponent': 'key_public_exponent',
            'encrypted': 'key_encrypted',
            'passphrase': 'key_passphrase',
            'passphrase_value': 'key_passphrase_value',
            'passphrase_file': 'key_passphrase_file',
            'passphrase_random': 'key_passphrase_random',
            'passphrase_length': 'key_passphrase_length',
            'passphrase_character_set': 'key_passphrase_character_set',
        }

        if self.key is None:
            with self.ignore_readonly('key'):
                self.key = Key(** self._bind_arguments(property_bindings))

        self._bind_properties([{
            'object': self.key,
            'properties': property_bindings
        }])