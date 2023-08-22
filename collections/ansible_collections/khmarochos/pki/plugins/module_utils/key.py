from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from os import path
import q

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


class Key(FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
        'type': str
    },
    'llo': {'type': rsa.RSAPrivateKey},
    'file': {'mandatory': True},
    'size': {'type': int, 'default': Constants.DEFAULT_KEY_SIZE},
    'public_exponent': {'type': int, 'default': Constants.DEFAULT_KEY_PUBLIC_EXPONENT},
    'encrypted': {'type': bool, 'default': Constants.DEFAULT_KEY_ENCRYPTED},
    'passphrase': {'type': Passphrase},
    'passphrase_value': {'type': str, 'interpolate': FlexiClass.InterpolatorBehaviour.NEVER},
    'passphrase_file': {'mandatory': True, 'type': str},
    'passphrase_random': {'type': bool, 'default': Constants.DEFAULT_PASSPHRASE_RANDOM},
    'passphrase_length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'passphrase_character_set': {'type': str, 'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET},
    'encryption_algorithm': {
        'type': serialization.KeySerializationEncryption,
        'default': serialization.NoEncryption()
    },
}):

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        property_bindings = {
            'llo': 'passphrase_value',
            'file': 'passphrase_file',
            'random': 'passphrase_random',
            'length': 'passphrase_length',
            'character_set': 'passphrase_character_set',
        }

        if self.passphrase is None:
            with self.ignore_readonly('passphrase'):
                self.passphrase = Passphrase(** self._bind_arguments(property_bindings))

        self._bind_properties([{'object': self.passphrase, 'properties': property_bindings}])

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
            self.llo = serialization.load_pem_private_key(
                data=f.read(),
                password=self.passphrase.lookup().encode() if self.encrypted else None
            )

    def make_llo(self):
        with self.ignore_readonly('llo'):
            self.llo = rsa.generate_private_key(
                public_exponent=self.public_exponent,
                key_size=self.size
            )
        with self.ignore_readonly('encryption_algorithm'):
            self.encryption_algorithm = \
                serialization.BestAvailableEncryption(self.passphrase.lookup().encode()) \
                    if self.encrypted \
                    else serialization.NoEncryption()

    def save_llo(self):
        with open(self.file, 'wb') as f:
            f.write(self.llo.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=self.encryption_algorithm
            ))
