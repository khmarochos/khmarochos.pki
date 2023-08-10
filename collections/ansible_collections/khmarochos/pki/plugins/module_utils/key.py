from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from os import path
import q

from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


class Key(FlexiClass, properties={
    'key': {'type': rsa.RSAPrivateKey},
    'file': {'mandatory': True, 'type': str},
    'size': {'type': int, 'default': 4096},
    'public_exponent': {'type': int, 'default': 65537},
    'encrypted': {'type': bool},
    'passphrase': {'type': Passphrase},
    'passphrase_value': {'type': str, 'interpolate': FlexiClass.InterpolatorBehaviour.NEVER},
    'passphrase_file': {'mandatory': True, 'type': str},
    'passphrase_random': {'type': bool},
    'passphrase_length': {'type': int}
}):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def setup(self, force: bool = False):
        if self.passphrase is None:
            with self._ignore_readonly('passphrase'):
                self.passphrase = Passphrase(
                    passphrase=self.passphrase_value,
                    file=self.passphrase_file,
                    random=self.passphrase_random,
                    length=self.passphrase_length
                )
        self.passphrase.setup()

        if path.exists(self.file) and not force:
            self._load_key()
        else:
            self._update_key()

    def _load_key(self):
        with open(self.file, 'rb') as f, self._ignore_readonly('key'):
            self.key = serialization.load_pem_private_key(
                data=f.read(),
                password=self.passphrase.get_passphrase().encode() if self.encrypted else None
            )

    def _update_key(self):
        self._generate_key()
        self._save_key()

    def _generate_key(self):
        with self._ignore_readonly('key'):
            self.key = rsa.generate_private_key(
                public_exponent=self.public_exponent,
                key_size=self.size
            )

    def _save_key(self):
        q(self.passphrase.get_passphrase())
        with open(self.file, 'wb') as f:
            f.write(self.key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase.get_passphrase().encode()) if self.encrypted else serialization.NoEncryption()
            ))
