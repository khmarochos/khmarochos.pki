from os import path
import string
import secrets

from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class Passphrase(FlexiClass, properties={
    'passphrase': {'type': str},
    'file': {'type': str, 'mandatory': True},
    'random': {'type': bool},
    'length': {'type': int, 'default': 32},
    'character_set': {'type': str, 'default': string.ascii_letters + string.digits + string.punctuation}
}):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def setup(self, force: bool = False):
        if path.exists(self.file) and not force:
            self._load_passphrase()
        else:
            self._update_passphrase()

    def _load_passphrase(self):
        with open(self.file, 'r') as f, self._ignore_readonly('passphrase'):
            self.passphrase = f.read()

    def _save_passphrase(self):
        with open(self.file, 'w') as f:
            f.write(self.passphrase)

    def _update_passphrase(self):
        if self.random:
            self._generate_passphrase()
        self._save_passphrase()

    def _generate_passphrase(self):
        with self._ignore_readonly('passphrase'):
            self.passphrase = ''.join(secrets.choice(self.character_set) for _ in range(self.length))

    def get_passphrase(self) -> str:
        return self.passphrase
