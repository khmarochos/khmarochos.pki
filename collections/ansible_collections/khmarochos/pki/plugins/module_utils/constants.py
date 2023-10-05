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

import string
import enum


class CertificateTypes(enum.Enum):
    CA_STUBBY = 'CA_STUBBY'
    CA_INTERMEDIATE = 'CA_INTERMEDIATE'
    SERVER = 'SERVER'
    CLIENT = 'CLIENT'


class CertificateExtensionPurposes(enum.Enum):
    CA = 'CA'
    SAN = 'SAN'


class Constants:
    DEFAULT_CERTIFICATE_TERM = 90
    DEFAULT_PRIVATE_KEY_SIZE = 4096
    DEFAULT_PRIVATE_KEY_PUBLIC_EXPONENT = 0x10001   # 0d65537
    DEFAULT_PRIVATE_KEY_ENCRYPTED = False
    DEFAULT_PASSPHRASE_LENGTH = 32
    DEFAULT_PASSPHRASE_CHARACTER_SET = string.ascii_letters + string.digits + string.punctuation
    DEFAULT_PASSPHRASE_RANDOM = False
    DEFAULT_ROOT_DIRECTORY_MODE = 0o755
    DEFAULT_PRIVATE_DIRECTORY_MODE = 0o700
    DEFAULT_CERTIFICATE_SIGNING_REQUESTS_DIRECTORY_MODE = 0o755
    DEFAULT_CERTIFICATES_DIRECTORY_MODE = 0o755
    DEFAULT_CERTIFICATE_REVOCATION_LISTS_DIRECTORY_MODE = 0o755



