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

from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes


def translate_certificate_parameters(certificate_parameters: dict = None, clone: bool = True):
    if certificate_parameters is None:
        certificate_parameters = {}
    if clone:
        certificate_parameters = certificate_parameters.copy()
    if certificate_parameters.get('certificate_type') is not None:
        certificate_parameters['certificate_type'] = CertificateTypes[certificate_parameters['certificate_type'].upper()]
    return certificate_parameters
