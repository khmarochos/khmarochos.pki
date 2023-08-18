from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from os import path
import string
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

    def setup(self, force: bool = False):
        if self.encrypted:
            if self.passphrase is None:
                with self.ignore_readonly('passphrase'):
                    self.passphrase = Passphrase(
                        passphrase=self.passphrase_value,
                        file=self.passphrase_file,
                        random=self.passphrase_random,
                        length=self.passphrase_length
                    )
            self.passphrase.setup()

        if path.exists(self.file) and not force:
            self._load()
        else:
            self._build()

    def _load(self):
        with open(self.file, 'rb') as f, self.ignore_readonly('key'):
            self.key = serialization.load_pem_private_key(
                data=f.read(),
                password=self.passphrase.lookup().encode() if self.encrypted else None
            )

    def _build(self):
        self._generate()
        self._save()

    def _generate(self):
        with self.ignore_readonly('key'):
            self.key = rsa.generate_private_key(
                public_exponent=self.public_exponent,
                key_size=self.size
            )
        with self.ignore_readonly('encryption_algorithm'):
            self.encryption_algorithm = \
                serialization.BestAvailableEncryption(self.passphrase.lookup().encode()) \
                    if self.encrypted \
                    else serialization.NoEncryption()

    def _save(self):
        with open(self.file, 'wb') as f:
            f.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=self.encryption_algorithm
            ))
