from os import path
import string
import secrets

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class Passphrase(FlexiClass, properties={
    'passphrase': {'type': str},
    'file': {'type': str, 'mandatory': True},
    'random': {'type': bool, 'default': Constants.DEFAULT_PASSPHRASE_RANDOM},
    'length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'character_set': {'type': str, 'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET}
}):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def setup(self, force: bool = False):
        if path.exists(self.file) and not force:
            self._load()
        else:
            self._make()

    def _load(self):
        with open(self.file, 'r') as f, self.ignore_readonly('passphrase'):
            self.passphrase = f.read()

    def _save(self):
        with open(self.file, 'w') as f:
            f.write(self.passphrase)

    def _make(self):
        if self.random:
            self._generate()
        elif self.passphrase is None:
            raise ValueError('Passphrase is not set')
        self._save()

    def _generate(self):
        with self.ignore_readonly('passphrase'):
            self.passphrase = ''.join(secrets.choice(self.character_set) for _ in range(self.length))

    def lookup(self) -> str:
        return self.passphrase
