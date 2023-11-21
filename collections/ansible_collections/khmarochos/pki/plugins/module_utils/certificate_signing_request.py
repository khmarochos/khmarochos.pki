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

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from ansible_collections.khmarochos.pki.plugins.module_utils.certificate_base import CertificateBase
from ansible_collections.khmarochos.pki.plugins.module_utils.change_tracker import ChangeTracker
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass
from ansible_collections.khmarochos.pki.plugins.module_utils.private_key import PrivateKey


class CertificateSigningRequest(ChangeTracker, CertificateBase, FlexiClass, properties={
    FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
        'mandatory': False,
        'default': None,
        'readonly': True,
        'interpolate': FlexiClass.InterpolatorBehaviour.NEVER,
        'type': str
    },
    'nickname': {'mandatory': True},
    'llo': {'type': x509.CertificateSigningRequest},
    'file': {'mandatory': True},
    'certificate_type': {'type': CertificateTypes},
    'subject': {'type': x509.name.Name},
    'subject_alternative_names': {'type': list},
    'extra_extensions': {'type': list},
    'private_key': {'type': PrivateKey},
}):

    def load(self, anatomize_llo: bool = True):
        with open(self.file, 'rb') as f, self.ignore_readonly('llo'):
            self.llo = x509.load_pem_x509_csr(f.read())
        if anatomize_llo:
            self.anatomize_llo()

