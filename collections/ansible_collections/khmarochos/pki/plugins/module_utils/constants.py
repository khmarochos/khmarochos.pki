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
    CA_STUBBY = 'ca_stubby'
    CA_INTERMEDIATE = 'ca_intermediate'
    SERVER = 'server'
    CLIENT = 'client'


class Constants:
    DEFAULT_CERTIFICATE_TERM = 300
    DEFAULT_KEY_SIZE = 4096
    DEFAULT_KEY_PUBLIC_EXPONENT = 65537
    DEFAULT_KEY_ENCRYPTED = False
    DEFAULT_PASSPHRASE_LENGTH = 32
    DEFAULT_PASSPHRASE_CHARACTER_SET = string.ascii_letters + string.digits + string.punctuation
    DEFAULT_PASSPHRASE_RANDOM = False

