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

from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangeTracker
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import Constants
from ansible_collections.khmarochos.pki.plugins.module_utils.flexibuilder import FlexiBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase import Passphrase


class PrivateKeyBuilder(ChangeTracker, FlexiBuilder, properties={
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
    'encryption_algorithm': {'type': serialization.KeySerializationEncryption},
    'passphrase': {'type': Passphrase}
}):

    @FlexiBuilder.parameters_assigner
    def _assign_parameters(
            self,
            parameters_to_assign: dict = None,
            parameters_to_merge: dict = None,
            parameters_assigned: dict = None
    ) -> dict:

        if parameters_assigned.get('encrypted') is True:
            if parameters_assigned.get('passphrase') is None:
                raise ValueError('The passphrase parameter cannot be None if the encrypted parameter is True')
            elif isinstance(parameters_assigned.get('encryption_algorithm'), serialization.NoEncryption):
                raise ValueError('The encryption_algorithm parameter cannot be serialization.NoEncryption '
                                 'if the encrypted parameter is True')
            elif parameters_assigned.get('encryption_algorithm') is None:
                parameters_assigned['encryption_algorithm'] = serialization.BestAvailableEncryption(
                    parameters_assigned.get('passphrase').lookup().encode()
                )
        else:
            if parameters_assigned.get('passphrase') is not None:
                raise ValueError('The passphrase parameter cannot be set if the encrypted parameter is False')
            elif parameters_assigned.get('encryption_algorithm') is None:
                parameters_assigned['encryption_algorithm'] = serialization.NoEncryption()
            elif not isinstance(parameters_assigned.get('encryption_algorithm'), serialization.NoEncryption):
                raise ValueError('The encryption_algorithm parameter must be serialization.NoEncryption '
                                 'if the encrypted parameter is False')

        return parameters_assigned

    @staticmethod
    def _check_after_load(
            private_key: PrivateKey,
            parameters_assigned: dict,
            raise_exception: bool = True
    ) -> bool:
        result = FlexiBuilder.check_after_load_universal(
            object_to_check=private_key,
            parameters_assigned=parameters_assigned,
            parameters_to_check=['size', 'public_exponent', 'encrypted', 'passphrase'],
            raise_exception=raise_exception
        )
        if not isinstance(private_key.encryption_algorithm, type(parameters_assigned.get('encryption_algorithm'))):
            if raise_exception:
                raise RuntimeError(f"The private key has been loaded, "
                                   f"its encryption algorithm ({private_key.encryption_algorithm}) differs from "
                                   f"the expected encryption algorithm "
                                   f"({parameters_assigned.get('encryption_algorithm')})")
            else:
                result = False
        return result

    def init_with_file(
            self,
            nickname: str = None,
            file: str = None,
            encrypted: bool = None,
            encryption_algorithm: serialization.KeySerializationEncryption = None,
            passphrase: Passphrase = None
    ) -> PrivateKey:
        parameters_assigned = self._assign_parameters({
            'nickname': {'mandatory': True},
            'file': {'mandatory': True},
            'encrypted': {},
            'encryption_algorithm': {},
            'passphrase': {}
        })
        private_key = PrivateKey(**parameters_assigned)
        private_key.load()
        PrivateKeyBuilder._check_after_load(private_key, parameters_assigned)
        return private_key

    def init_with_llo(
            self,
            nickname: str = None,
            llo: rsa.RSAPrivateKey = None,
            file: str = None,
            encrypted: bool = None,
            encryption_algorithm: serialization.KeySerializationEncryption = None,
            passphrase: Passphrase = None,
            save_if_needed: bool = True,
            save_forced: bool = True
    ) -> PrivateKey:
        parameters_assigned = self._assign_parameters({
            'nickname': {'mandatory': True},
            'llo': {'mandatory': True},
            'file': {'mandatory': True},
            'encrypted': {},
            'encryption_algorithm': {},
            'passphrase': {}
        })
        private_key = PrivateKey(**parameters_assigned)
        private_key.anatomize_llo()
        PrivateKeyBuilder._check_after_load(private_key, parameters_assigned)
        file_exists = os.path.exists(parameters_assigned.get('file'))
        if save_forced or save_if_needed and not file_exists:
            private_key.save()
            self.changes_stack.state("Saved a private key")
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
            save_if_needed: bool = True,
            save_forced: bool = False
    ) -> PrivateKey:
        parameters_assigned = self._assign_parameters({
            'nickname': {'mandatory': True},
            'file': {'mandatory': True},
            'size': {},
            'public_exponent': {},
            'encrypted': {},
            'encryption_algorithm': {},
            'passphrase': {}
        })
        generated = False
        if load_if_exists and os.path.isfile(parameters_assigned.get('file')):
            private_key = self.init_with_file(
                **{
                    k: v for k, v in parameters_assigned.items() if k in [
                        'nickname',
                        'file',
                        'encrypted',
                        'encryption_algorithm',
                        'passphrase'
                    ]
                }
            )
            PrivateKeyBuilder._check_after_load(private_key, parameters_assigned)
        else:
            private_key = PrivateKey(**parameters_assigned)
            private_key.generate()
            generated = True
        if save_forced or (save_if_needed and generated):
            private_key.save()
            self.changes_stack.state("Saved a private key")
        return private_key
