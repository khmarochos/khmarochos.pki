# Copyright 2023 Volodymyr Melnyk
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangeTracker
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


class PrivateKey(ChangeTracker, FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'type': str,
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
    },
    'nickname': {'mandatory': True},
    'llo': {'type': rsa.RSAPrivateKey},
    'file': {'mandatory': True},
    'size': {'type': int, 'default': Constants.DEFAULT_PRIVATE_KEY_SIZE},
    'public_modulus': {'type': int},
    'public_exponent': {'type': int, 'default': Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT},
    'public_key': {'type': rsa.RSAPublicKey},
    'encrypted': {'type': bool, 'default': Constants.DEFAULT_PRIVATE_KEY_ENCRYPTED},
    'encryption_algorithm': {'type': serialization.KeySerializationEncryption},
    'passphrase': {'type': Passphrase},
}):

    def load(self, anatomize_llo: bool = True):
        with open(self.file, 'rb') as f, self.ignore_readonly('llo'), self.ignore_readonly('encryption_algorithm'):
            self.llo = serialization.load_pem_private_key(
                data=f.read(),
                password=self.passphrase.lookup().encode() if self.encrypted else None
            )
            if not self.property_updated('encryption_algorithm'):
                if self.encrypted:
                    self.encryption_algorithm = serialization.BestAvailableEncryption(self.passphrase.lookup().encode())
                else:
                    self.encryption_algorithm = serialization.NoEncryption()
        if anatomize_llo:
            self.anatomize_llo()

    def generate(self, anatomize_llo: bool = True):
        with self.ignore_readonly('llo'):
            self.llo = rsa.generate_private_key(
                public_exponent=self.public_exponent,
                key_size=self.size
            )
        if anatomize_llo:
            self.anatomize_llo()

    def anatomize_llo(self):
        with self.ignore_readonly('size'):
            self.size = self.llo.key_size
        with self.ignore_readonly('public_modulus'):
            self.public_modulus = self.llo.public_key().public_numbers().n
        with self.ignore_readonly('public_exponent'):
            self.public_exponent = self.llo.public_key().public_numbers().e
        with self.ignore_readonly('public_key'):
            self.public_key = self.llo.public_key()
        with self.ignore_readonly('encryption_algorithm'):
            if self.encrypted:
                self.encryption_algorithm = serialization.BestAvailableEncryption(self.passphrase.lookup().encode())
            else:
                self.encryption_algorithm = serialization.NoEncryption()

    def save(self):
        with open(self.file, 'wb') as f:
            f.write(self.get_pem())

    def get_pem(self):
        return self.llo.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self.encryption_algorithm
        )
