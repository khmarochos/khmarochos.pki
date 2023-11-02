import logging
import sys
import unittest
import yaml

from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade import PKICascade
from ansible_collections.khmarochos.pki.plugins.module_utils.constants import CertificateTypes

logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler(sys.stdout)])


class InitCascadeTest(unittest.TestCase):

    def setUp(self):
        with open("test-case-full.yaml", "r") as stream:
            self.pki_cascade_configuration = (yaml.safe_load(stream))["pki_ca_cascade"]

    def test_initialisation(self):
        pki_cascade = PKICascade(self.pki_cascade_configuration)
        self.assertTrue(type(pki_cascade), PKICascade)
        logging.debug(pki_cascade.pki_cascade_json(pretty=True))

    def test_load(self):
        pki_cascade = PKICascade(self.pki_cascade_configuration)
        pki_cascade.setup()
        logging.debug(pki_cascade.pki_cascade_json(pretty=True))

    def test_pki_issue(self):
        pki_cascade = PKICascade(self.pki_cascade_configuration)
        pki_cascade.setup()
        for pki_ca in pki_cascade.pki_cascade.values():
            certificate = pki_ca.issue(
                nickname='test',
                certificate_type=CertificateTypes.CLIENT,
                certificate_term=1,
                private_key_encrypted=True,
                private_key_passphrase_random=True
            )
            logging.debug(certificate.get_properties())

if __name__ == '__main__':
    unittest.main()
