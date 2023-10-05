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

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexibuilder import FlexiBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


class PrivateKeyBuilder(FlexiBuilder, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'type': str,
        'mandatory': False,
        'readonly': False,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
        'add_builder_updater': True
    },
    'nickname': {},
    'llo': {'type': rsa.RSAPrivateKey},
    'file': {},
    'size': {'type': int, 'default': Constants.DEFAULT_PRIVATE_KEY_SIZE},
    'public_exponent': {'type': int, 'default': Constants.DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT},
    'encrypted': {'type': bool, 'default': Constants.DEFAULT_PRIVATE_KEY_ENCRYPTED},
    'encryption_algorithm': {
        'type': serialization.KeySerializationEncryption,
        'default': serialization.NoEncryption()
    },
    'passphrase': {'type': Passphrase}
}):

    def init_with_file(
            self,
            nickname: str = None,
            file: str = None,
            encrypted: bool = None,
            passphrase: Passphrase = None
    ) -> PrivateKey:
        if (nickname := self._from_kwargs_or_properties('nickname')) is None:
            raise ValueError('The nickname parameter cannot be None')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if encrypted := self._from_kwargs_or_properties('encrypted'):
            if (passphrase := self._from_kwargs_or_properties('passphrase')) is None:
                raise ValueError('The passphrase parameter cannot be None')
        private_key = PrivateKey(nickname=nickname, file=file, encrypted=encrypted, passphrase=passphrase)
        private_key.load()
        return private_key

    def init_with_llo(
            self,
            nickname: str = None,
            llo: rsa.RSAPrivateKey = None,
            file: str = None,
            encrypted: bool = None,
            passphrase: Passphrase = None,
            save: bool = True
    ) -> PrivateKey:
        if (nickname := self._from_kwargs_or_properties('nickname')) is None:
            raise ValueError('The nickname parameter cannot be None')
        if (llo := self._from_kwargs_or_properties('llo')) is None:
            raise ValueError('The llo parameter cannot be None')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if encrypted := self._from_kwargs_or_properties('encrypted'):
            if (passphrase := self._from_kwargs_or_properties('passphrase')) is None:
                raise ValueError('The passphrase parameter cannot be None')
        private_key = PrivateKey(
            nickname=nickname,
            file=file,
            llo=llo,
            encrypted=encrypted,
            passphrase=passphrase
        )
        private_key.anatomize_llo()
        if save:
            private_key.save()
        return private_key

    def init_new(
            self,
            nickname: str = None,
            file: str = None,
            size: int = None,
            public_exponent: int = None,
            encrypted: bool = None,
            encryption_algorithm: serialization.KeySerializationEncryption = None,
            passphrase: Passphrase = None,
            load_if_exists: bool = False,
            save: bool = True
    ) -> PrivateKey:
        if (nickname := self._from_kwargs_or_properties('nickname')) is None:
            raise ValueError('The nickname parameter cannot be None')
        if (file := self._from_kwargs_or_properties('file')) is None:
            raise ValueError('The file parameter cannot be None')
        if (size := self._from_kwargs_or_properties('size')) < 1:
            raise ValueError('The size parameter cannot be less than 1')
        if (public_exponent := self._from_kwargs_or_properties('public_exponent')) < 1:
            raise ValueError('The public_exponent parameter cannot be less than 1')
        encrypted = self._from_kwargs_or_properties('encrypted')
        encryption_algorithm = self._from_kwargs_or_properties('encryption_algorithm')
        passphrase = self._from_kwargs_or_properties('passphrase')
        if encrypted:
            if encryption_algorithm is None:
                raise ValueError('The encryption_algorithm parameter cannot be None')
            if passphrase is None:
                raise ValueError('The passphrase parameter cannot be None')
        private_key = None
        if load_if_exists and os.path.isfile(file):
            private_key = self.init_with_file(
                nickname=nickname,
                file=file,
                encrypted=encrypted,
                passphrase=passphrase
            )
            if private_key.size != size:
                raise RuntimeError(f"The private key {file} already exists, "
                                   f"its size ({private_key.size}) differs from the expected size ({size})")
            if private_key.public_exponent != public_exponent:
                raise RuntimeError(f"The private key {file} already exists, "
                                   f"its public exponent ({private_key.public_exponent}) differs from "
                                   f"the expected public exponent ({public_exponent})")
            if private_key.encrypted != encrypted:
                raise RuntimeError(f"The private key {file} already exists, "
                                   f"its encrypted ({private_key.encrypted}) differs from "
                                   f"the expected encrypted ({encrypted})")
            if not isinstance(private_key.encryption_algorithm, type(encryption_algorithm)):
                raise RuntimeError(f"The private key {file} already exists, "
                                   f"its encryption algorithm ({private_key.encryption_algorithm}) differs from "
                                   f"the expected encryption algorithm ({encryption_algorithm})")
            if private_key.passphrase and private_key.passphrase != passphrase:
                raise RuntimeError(f"The private key {file} already exists, "
                                   f"its passphrase ({private_key.passphrase}) differs from "
                                   f"the expected passphrase ({passphrase})")
        if private_key is None:
            private_key = PrivateKey(
                nickname=nickname,
                file=file,
                size=size,
                public_exponent=public_exponent,
                encrypted=encrypted,
                passphrase=passphrase
            )
            private_key.generate()
            if save:
                private_key.save()
        return private_key
