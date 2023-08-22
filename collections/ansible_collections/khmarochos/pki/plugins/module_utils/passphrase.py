from os import path
import string
import secrets

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class Passphrase(FlexiClass, properties={
    'llo': {'type': str},
    'file': {'type': str, 'mandatory': True},
    'random': {'type': bool, 'default': Constants.DEFAULT_PASSPHRASE_RANDOM},
    'length': {'type': int, 'default': Constants.DEFAULT_PASSPHRASE_LENGTH},
    'character_set': {'type': str, 'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET}
}):

    # def __init__(self, **kwargs):
    #     super().__init__(**kwargs)

    def setup(self):
        self.setup_llo()

    def setup_llo(self, force_save: bool = False, force_load: bool = False):
        generated = False
        if getattr(self, 'llo') is None or force_load:
            try:
                self.load_llo()
            except FileNotFoundError:
                if self.random:
                    self.make_llo()
                    generated = True
        if generated or force_save:
            self.save_llo()

    def load_llo(self):
        with open(self.file, 'r') as f, self.ignore_readonly('llo'):
            self.llo = f.read()

    def save_llo(self):
        with open(self.file, 'w') as f:
            f.write(self.llo)

    def make_llo(self):
        with self.ignore_readonly('llo'):
            self.llo = ''.join(secrets.choice(self.character_set) for _ in range(self.length))

    def lookup(self) -> str:
        return self.llo
