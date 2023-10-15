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
import logging
import random
import secrets
import tempfile
import unittest
import warnings
from enum import Enum
from abc import ABC, abstractmethod
from typing import TypeVar, Any, Tuple, Union, List

from cryptography import x509

from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass \
    import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.constants \
    import Constants, CertificateTypes
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_builder_base \
    import CertificateBuilderBase
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate \
    import Certificate
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_builder \
    import CertificateBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request \
    import CertificateSigningRequest
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key \
    import PrivateKey
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key_builder \
    import PrivateKeyBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_signing_request_builder \
    import CertificateSigningRequestBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase \
    import Passphrase
from ansible_collections.khmarochos.pki.plugins.module_utils.passphrase_builder \
    import PassphraseBuilder


DOMAIN_NAME = 'kloudster.com'
DEFAULT_CERTIFICATE_SUBJECT_COUNTRY_NAME = 'PL'
DEFAULT_CERTIFICATE_SUBJECT_STATE_OR_PROVINCE_NAME = 'Malopolskie'
DEFAULT_CERTIFICATE_SUBJECT_LOCALITY_NAME = 'Krakow'
DEFAULT_CERTIFICATE_SUBJECT_ORGANIZATION_NAME = 'TUCHA SPOLKA Z OGRANICZONA ODPOWIEDZIALNOSCIA'
DEFAULT_CERTIFICATE_SUBJECT_ORGANIZATIONAL_UNIT_NAME = 'Security Service'
DEFAULT_CERTIFICATE_SUBJECT_EMAIL_ADDRESS = f'security@{DOMAIN_NAME}'
DEFAULT_CERTIFICATE_SUBJECT_COMMON_NAME = f'security.{DOMAIN_NAME}'
RANDOM_STRING_MIN_LENGTH = 16
RANDOM_STRING_MAX_LENGTH = 32
RANDOM_STRING_CHARSET = ''.join([chr(i) for i in range(0x21, 0x7F)])
RANDON_NICKNAME_MIN_LENGTH = 8
RANDOM_NICKNAME_MAX_LENGTH = 32
RANDOM_NICKNAME_CHARACTER_SET = 'abcdefghijklmnopqrstuvwxyz'
RANDOM_CERTIFICATE_SUBJECT_COMMON_NAME_MIN_LENGTH = 8
RANDOM_CERTIFICATE_SUBJECT_COMMON_NAME_MAX_LENGTH = 32
RANDOM_CERTIFICATE_SUBJECT_COMMON_NAME_CHARACTER_SET = 'abcdefghijklmnopqrstuvwxyz'
MIN_RANDOM_CERTIFICATE_TERM = 13
MAX_RANDOM_CERTIFICATE_TERM = 666


class BuilderTestType(Enum):
    SKIP = 'skip'
    EQUAL = 'equal'
    NOT_EQUAL = 'not_equal'
    NONE = 'none'
    NOT_NONE = 'not_none'
    ZERO = 'zero'
    NON_ZERO = 'non_zero'
    EMPTY = 'empty'
    NOT_EMPTY = 'not_empty'
    TRUE = 'true'
    FALSE = 'false'
    ISINSTANCE = 'isinstance'
    NOT_ISINSTANCE = 'not_isinstance'
    IN = 'in'
    NOT_IN = 'not_in'
    LAMBDA = 'lambda'

class StopAfter(Enum):
    DO_NOT_RUN = 0,
    PASSPHRASE = 1,
    PRIVATE_KEY = 2,
    CERTIFICATE_SIGNING_REQUEST = 3,
    CERTIFICATE = 4

__T = TypeVar("__T")
BuilderCheckListElement = Union[Tuple[BuilderTestType], Tuple[BuilderTestType, Any], __T]
BuilderCheckList = Union[BuilderCheckListElement[__T], List[BuilderCheckListElement[__T]]]


class Randomizer(FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'type': str,
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER
    },
    'min_random_string_length': {'type': int, 'default': RANDOM_STRING_MIN_LENGTH},
    'max_random_string_length': {'type': int, 'default': RANDOM_STRING_MAX_LENGTH},
    'character_set': {'default': Constants.DEFAULT_PASSPHRASE_CHARACTER_SET}
}):

    def _random_number(
            self,
            min_allowed: int,
            max_allowed: int,
            disallowed: list = None
    ) -> int:
        disallowed = set(disallowed) if disallowed is not None else set()
        random_number = random.randint(min_allowed, max_allowed)
        if random_number not in disallowed:
            return random_number
        lower_bound, upper_bound = random_number, random_number
        lower_bound_reached, upper_bound_reached = False, False
        while True:
            if lower_bound_reached is False and (lower_bound := lower_bound - 1) >= min_allowed:
                if lower_bound not in disallowed:
                    return lower_bound
            else:
                lower_bound_reached = True
            if upper_bound_reached is False and (upper_bound := upper_bound + 1) <= max_allowed:
                if upper_bound not in disallowed:
                    return upper_bound
            else:
                upper_bound_reached = True
            if lower_bound_reached and upper_bound_reached:
                raise RuntimeError('Unable to generate a random number that would differ from the disallowed numbers')

    def _random_string(self, length: int = None, character_set: str = None) -> str:
        if length is None:
            length: int = self._random_number(self.min_random_string_length, self.max_random_string_length)
        if character_set is None:
            character_set: str = self.character_set
        return ''.join(secrets.choice(character_set) for _ in range(length))

    def randomize_nickname(self, length: int = None, character_set: str = None) -> str:
        return self._random_string(length=length, character_set=RANDOM_NICKNAME_CHARACTER_SET)

    def randomize_certificate_subject_common_name(self, length: int = None, character_set: str = None) -> str:
        return self._random_string(length=length, character_set=character_set) + '.' + DOMAIN_NAME

    def randomize_certificate_term(
            self,
            min_term: int = MIN_RANDOM_CERTIFICATE_TERM,
            max_term: int = MAX_RANDOM_CERTIFICATE_TERM
    ) -> int:
        return self._random_number(min_term, max_term, disallowed=[Constants.DEFAULT_CERTIFICATE_TERM])

    def randomize_passphrase_length(
            self,
            min_length: int = RANDOM_STRING_MIN_LENGTH,
            max_length: int = RANDOM_STRING_MAX_LENGTH
    ) -> int:
        return self._random_number(min_length, max_length, disallowed=[Constants.DEFAULT_PASSPHRASE_LENGTH])

    def randomize_passphrase_character_set(
            self,
            min_length: int = None,
            max_length: int = None
    ) -> str:
        chars = [chr(i) for i in range(0x21, 0x7F)]
        random.shuffle(chars)
        if min_length is None:
            min_length = 1
        elif min_length < 1:
            warnings.warn('The minimal passphrase length cannot be less than 1, setting it to 1')
            min_length = 1
        if max_length is None:
            max_length = len(chars)
        elif max_length > len(chars):
            warnings.warn(f'The maximal passphrase length cannot be greater than {len(chars)}, setting it to {len(chars)}')
            max_length = len(chars)
        if min_length > max_length:
            warnings.warn(f'The minimal passphrase length cannot be greater than the maximal passphrase length, swapping them')
            min_length, max_length = max_length, min_length
        return ''.join(sorted(chars[:self._random_number(min_length, max_length - 1)]))


# noinspection PyProtectedMember
class TestingSet(FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'type': str,
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER
    },
    'stop_after': {'type': StopAfter, 'default': StopAfter.DO_NOT_RUN},
    'nickname': {'type': Union[str, Randomizer]},
    'nickname_charset': {'default': 'abcdefghijklmnopqrstuvwxyz'},
    'nickname_minimal_length': {'type': int, 'default': 8},
    'nickname_maximal_length': {'type': int, 'default': 32},
    'passphrase': {'type': Passphrase},
    'passphrase_file': {'type': tempfile._TemporaryFileWrapper},
    'passphrase_file_name': {},
    'passphrase_random': {'type': bool, 'default': True},
    'passphrase_length': {'type': Union[int, Randomizer]},
    'passphrase_character_set': {'type': Union[str, Randomizer]},
    'passphrase_minimal_length': {'type': int, 'default': 8},
    'passphrase_maximal_length': {'type': int, 'default': 32},
    'passphrase_value': {},
    'private_key': {'type': PrivateKey},
    'private_key_file': {'type': tempfile._TemporaryFileWrapper},
    'private_key_file_name': {},
    'certificate_signing_request': {'type': CertificateSigningRequest},
    'certificate_signing_request_file': {'type': tempfile._TemporaryFileWrapper},
    'certificate_signing_request_file_name': {},
    'certificate': {'type': Certificate},
    'certificate_file': {'type': tempfile._TemporaryFileWrapper},
    'certificate_file_name': {},
    'certificate_chain_file': {'type': tempfile._TemporaryFileWrapper},
    'certificate_chain_file_name': {},
    'certificate_type': {'type': CertificateTypes},
    'certificate_term': {'type': Union[int, Randomizer]},
    'certificate_subject': {'type': x509.name.Name},
    'certificate_subject_common_name': {'type': Union[str, Randomizer]},
    'certificate_alternative_names': {'type': Union[list, Randomizer]},
    'certificate_alternative_names_number': {'type': int, 'default': 5},
    'certificate_extra_extensions': {'type': list},
    'certificate_issuer_private_key': {'type': PrivateKey},
    'certificate_issuer_subject': {'type': x509.name.Name},
}):

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        #
        # Configuring the parameters
        #

        # The nickname
        if self.nickname is None:
            raise ValueError('The nickname parameter cannot be None')
        elif isinstance(self.nickname, Randomizer):
            with self.ignore_readonly('nickname'):
                self.nickname = self.nickname.randomize_nickname()

        # The passphrase-related parameters
        if self.stop_after.value >= StopAfter.PASSPHRASE.value:
            if self.passphrase_file_name is not None:
                raise ValueError('The passphrase_file_name parameter cannot be set manually')
            if self.passphrase_file is None:
                with self.ignore_readonly('passphrase_file'):
                    self.passphrase_file = tempfile.NamedTemporaryFile(
                        prefix='f{nickname}.',
                        suffix='.passphrase.txt',
                    )
                with self.ignore_readonly('passphrase_file_name'):
                    self.passphrase_file_name = self.passphrase_file.name
            if self.passphrase_random:
                if isinstance(self.passphrase_length, Randomizer):
                    with self.ignore_readonly('passphrase_length'):
                        self.passphrase_length = self.passphrase_length.randomize_passphrase_length(
                            min_length=self.passphrase_minimal_length,
                            max_length=self.passphrase_maximal_length
                        )
                if isinstance(self.passphrase_character_set, Randomizer):
                    with self.ignore_readonly('passphrase_character_set'):
                        self.passphrase_character_set = self.passphrase_character_set.randomize_passphrase_character_set()

        # The private key-related parameters
        if self.stop_after.value >= StopAfter.PRIVATE_KEY.value:
            if self.private_key_file_name is not None:
                raise ValueError('The private_key_file_name parameter cannot be set manually')
            if self.private_key_file is None:
                with self.ignore_readonly('private_key_file'):
                    self.private_key_file = tempfile.NamedTemporaryFile(
                        prefix=f'{self.nickname}.',
                        suffix='.private_key.pem',
                    )
                with self.ignore_readonly('private_key_file_name'):
                    self.private_key_file_name = self.private_key_file.name

        if self.stop_after.value >= StopAfter.CERTIFICATE_SIGNING_REQUEST.value:
            # The certificate signing request-related parameters
            # ...certificate_signing_request_file_name
            if self.certificate_signing_request_file_name is not None:
                raise ValueError('The certificate_signing_request_file_name parameter cannot be set manually')
            # ...certificate_signing_request_file
            if self.certificate_signing_request_file is None:
                with self.ignore_readonly('certificate_signing_request_file'):
                    self.certificate_signing_request_file = tempfile.NamedTemporaryFile(
                        prefix=f'{self.nickname}.',
                        suffix='.csr.pem',
                    )
                with self.ignore_readonly('certificate_signing_request_file_name'):
                    self.certificate_signing_request_file_name = self.certificate_signing_request_file.name
            # ...certificate_subject
            if isinstance(self.certificate_subject_common_name, Randomizer):
                with self.ignore_readonly('certificate_subject_common_name'):
                    self.certificate_subject_common_name = self.certificate_subject_common_name.randomize_certificate_subject_common_name()
            if self.certificate_subject_common_name is not None:
                with self.ignore_readonly('certificate_subject'):
                    self.certificate_subject = x509.name.Name([
                        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, DEFAULT_CERTIFICATE_SUBJECT_COUNTRY_NAME),
                        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, DEFAULT_CERTIFICATE_SUBJECT_STATE_OR_PROVINCE_NAME),
                        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, DEFAULT_CERTIFICATE_SUBJECT_LOCALITY_NAME),
                        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, DEFAULT_CERTIFICATE_SUBJECT_ORGANIZATION_NAME),
                        x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, DEFAULT_CERTIFICATE_SUBJECT_ORGANIZATIONAL_UNIT_NAME),
                        x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, DEFAULT_CERTIFICATE_SUBJECT_EMAIL_ADDRESS),
                        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, self.certificate_subject_common_name)
                    ])
            if self.certificate_subject is None:
                with self.ignore_readonly('certificate_subject'):
                    self.certificate_subject = x509.name.Name([
                        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, DEFAULT_CERTIFICATE_SUBJECT_COUNTRY_NAME),
                        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, DEFAULT_CERTIFICATE_SUBJECT_STATE_OR_PROVINCE_NAME),
                        x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, DEFAULT_CERTIFICATE_SUBJECT_LOCALITY_NAME),
                        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, DEFAULT_CERTIFICATE_SUBJECT_ORGANIZATION_NAME),
                        x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, DEFAULT_CERTIFICATE_SUBJECT_ORGANIZATIONAL_UNIT_NAME),
                        x509.NameAttribute(x509.oid.NameOID.EMAIL_ADDRESS, DEFAULT_CERTIFICATE_SUBJECT_EMAIL_ADDRESS),
                        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, self.nickname + '.' + DOMAIN_NAME),
                    ])
            # ...certificate_alternative_names
            if isinstance(self.certificate_alternative_names, Randomizer):
                certificate_alternative_names = []
                for _ in range(0, self.certificate_alternative_names_number - 1):
                    certificate_alternative_names.append(self.certificate_alternative_names.randomize_certificate_subject_common_name())
                with self.ignore_readonly('certificate_alternative_names'):
                    self.certificate_alternative_names = certificate_alternative_names

        if self.stop_after.value >= StopAfter.CERTIFICATE.value:
            # The certificate-related parameters
            # ...certificate_file_name
            if self.certificate_file_name is not None:
                raise ValueError('The certificate_file_name parameter cannot be set manually')
            # ...certificate_file
            if self.certificate_file is None:
                with self.ignore_readonly('certificate_file'):
                    self.certificate_file = tempfile.NamedTemporaryFile(
                        prefix=f'{self.nickname}.',
                        suffix='.crt.pem',
                    )
            with self.ignore_readonly('certificate_file_name'):
                self.certificate_file_name = self.certificate_file.name
            # ...certificate_chain_file_name
            if self.certificate_chain_file_name is not None:
                raise ValueError('The certificate_chain_file_name parameter cannot be set manually')
            # ...certificate_chain_file
            if self.certificate_chain_file is None:
                with self.ignore_readonly('certificate_chain_file'):
                    self.certificate_chain_file = tempfile.NamedTemporaryFile(
                        prefix=f'{self.nickname}.',
                        suffix='.chain.crt.pem',
                    )
            with self.ignore_readonly('certificate_chain_file_name'):
                self.certificate_chain_file_name = self.certificate_chain_file.name
            # ...certificate_term
            if isinstance(self.certificate_term, Randomizer):
                with self.ignore_readonly('certificate_term'):
                    self.certificate_term = self.certificate_term.randomize_certificate_term()

        #
        # Initializing the objects
        #

        if self.stop_after.value >= StopAfter.PASSPHRASE.value:
            # Generating the passphrase
            passphrase_builder = PassphraseBuilder() \
                .add_file(self.passphrase_file_name) \
                .add_random(self.passphrase_random) \
                .add_length(self.passphrase_length) \
                .add_character_set(self.passphrase_character_set) \
                .add_value(self.passphrase_value)
            with self.ignore_readonly('passphrase'):
                if self.passphrase_random:
                    self.passphrase = passphrase_builder.init_with_random()
                else:
                    self.passphrase = passphrase_builder.init_with_value()

        if self.stop_after.value >= StopAfter.PRIVATE_KEY.value:
            # Generating the private key
            private_key_builder = PrivateKeyBuilder() \
                .add_nickname(self.nickname) \
                .add_file(self.private_key_file_name) \
                .add_passphrase(self.passphrase)
            with self.ignore_readonly('private_key'):
                self.private_key = private_key_builder.init_new()

        if self.stop_after.value >= StopAfter.CERTIFICATE_SIGNING_REQUEST.value:
            # Generating the certificate signing request
            certificate_signing_request_builder = CertificateSigningRequestBuilder() \
                .add_nickname(self.nickname) \
                .add_file(self.certificate_signing_request_file_name) \
                .add_certificate_type(self.certificate_type) \
                .add_private_key(self.private_key) \
                .add_subject(self.certificate_subject) \
                .add_alternative_names(self.certificate_alternative_names) \
                .add_extra_extensions(self.certificate_extra_extensions)
            with self.ignore_readonly('certificate_signing_request'):
                self.certificate_signing_request = certificate_signing_request_builder.init_new()

    def __del__(self):
        if self.passphrase_file is not None:
            self.passphrase_file.close()
        if self.private_key_file is not None:
            self.private_key_file.close()
        if self.certificate_signing_request_file is not None:
            self.certificate_signing_request_file.close()
        if self.certificate_file is not None:
            self.certificate_file.close()


class AbstractBuilderTest(ABC):

    @staticmethod
    def random_string(
            length: int = random.randrange(RANDOM_STRING_MIN_LENGTH, RANDOM_STRING_MAX_LENGTH),
            character_set: str = Constants.DEFAULT_PASSPHRASE_CHARACTER_SET
    ) -> str:
        return ''.join(secrets.choice(character_set) for _ in range(length))

    def _test_object(self: unittest.TestCase, _object_to_test, **kwargs) -> bool:

        def _test_value(check_type: BuilderTestType, actual_value, expected_value, failure_message_prefix: str) -> bool:

            if check_type == BuilderTestType.SKIP:
                pass
            elif check_type == BuilderTestType.EQUAL:
                self.assertEqual(
                    expected_value,
                    actual_value,
                    f"{failure_message_prefix}: expected {expected_value}, got {actual_value}"
                )

            elif check_type == BuilderTestType.NOT_EQUAL:
                self.assertNotEqual(
                    expected_value,
                    actual_value,
                    f"{failure_message_prefix}: expected anything but {expected_value}, got {actual_value}"
                )

            elif check_type == BuilderTestType.NONE:
                self.assertIsNone(
                    actual_value,
                    f"{failure_message_prefix}: expected None, got {actual_value}"
                )

            elif check_type == BuilderTestType.NOT_NONE:
                self.assertIsNotNone(
                    actual_value,
                    f"{failure_message_prefix}: expected anything but None, got {actual_value}"
                )

            elif check_type == BuilderTestType.ZERO:
                self.assertEqual(
                    0,
                    actual_value,
                    f"{failure_message_prefix}: expected 0, got {actual_value}"
                )

            elif check_type == BuilderTestType.NON_ZERO:
                self.assertNotEqual(
                    0,
                    actual_value,
                    f"{failure_message_prefix}: expected anything but 0, got {actual_value}"
                )

            elif check_type == BuilderTestType.EMPTY:
                self.assertEqual(
                    '',
                    actual_value,
                    f"{failure_message_prefix}: expected empty string, got {actual_value}"
                )

            elif check_type == BuilderTestType.NOT_EMPTY:
                self.assertNotEqual(
                    '',
                    actual_value,
                    f"{failure_message_prefix}: expected anything but empty string, got {actual_value}"
                )

            elif check_type == BuilderTestType.TRUE:
                self.assertTrue(
                    actual_value,
                    f"{failure_message_prefix}: expected True, got {actual_value}"
                )

            elif check_type == BuilderTestType.FALSE:
                self.assertFalse(
                    actual_value,
                    f"{failure_message_prefix}: expected False, got {actual_value}"
                )

            elif check_type == BuilderTestType.ISINSTANCE:
                if not isinstance(expected_value, type):
                    raise ValueError(f'Expected value {expected_value} is not a type')
                self.assertIsInstance(
                    actual_value,
                    expected_value,
                    f"{failure_message_prefix}: "
                    f"expected an instance of {expected_value}, got {actual_value}"
                    f" of type {type(actual_value)}"
                )

            elif check_type == BuilderTestType.NOT_ISINSTANCE:
                if not isinstance(expected_value, type):
                    raise ValueError(f'Expected value {expected_value} is not a type')
                self.assertNotIsInstance(
                    actual_value,
                    expected_value,
                    f"{failure_message_prefix}: "
                    f"expected anything but an instance of {expected_value}, got {actual_value}"
                    f" of type {type(actual_value)}"
                )

            elif check_type == BuilderTestType.IN:
                if not isinstance(expected_value, list):
                    raise ValueError(f'Expected value {expected_value} is not a list')
                self.assertIn(
                    expected_value,
                    actual_value,
                    f"{failure_message_prefix}: expected {actual_value} to be in {expected_value}"
                )

            elif check_type == BuilderTestType.NOT_IN:
                if not isinstance(expected_value, list):
                    raise ValueError(f'Expected value {expected_value} is not a list')
                self.assertNotIn(
                    expected_value,
                    actual_value,
                    f"{failure_message_prefix}: expected {actual_value} to be not in {expected_value}"
                )

            elif check_type == BuilderTestType.LAMBDA:
                if not isinstance(expected_value, type(lambda: None)):
                    raise ValueError(f'Expected value {expected_value} is not a lambda')
                self.assertTrue(
                    expected_value(actual_value),
                    f"{failure_message_prefix}: expected {actual_value} to pass lambda {expected_value}"
                )

            else:
                raise ValueError(f'Unknown check type {check_type}')

            return True

        def _test_values(
                check_type: BuilderTestType,
                expected_values,
                actual_value,
                failure_message_prefix: str = None
        ):
            for expected_value in expected_values if isinstance(expected_values, list) else [expected_values]:
                if (result := _test_value(
                        check_type,
                        actual_value,
                        expected_value,
                        failure_message_prefix
                )) is False:
                    return result
            return True

        for property_name, property_checks in kwargs.items():
            if property_checks is None:
                continue
            for property_check in property_checks if isinstance(property_checks, list) else [property_checks]:
                property_check_type = BuilderTestType.EQUAL
                expected_values = [property_check]
                if isinstance(property_check, tuple):
                    property_check_type = property_check[0]
                    if len(property_check) > 2:
                        expected_values = property_check[1:]
                    elif len(property_check) > 1:
                        expected_values = property_check[1]
                actual_value = getattr(_object_to_test, property_name)
                if (result := _test_values(
                        property_check_type,
                        expected_values,
                        actual_value,
                        f"Property {property_name} of {_object_to_test} failed expectations:"
                )) is False:
                    return result
        return True
