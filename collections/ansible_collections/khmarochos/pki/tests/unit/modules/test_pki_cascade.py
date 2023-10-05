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


    def test_load(self):
        pki_cascade = PKICascade(self.pki_cascade_configuration)
        for pki_ca in pki_cascade.pki_cascade.values():
            pki_ca.setup()


    def test_pki_cascade_json(self):
        pki_cascade = PKICascade(self.pki_cascade_configuration)
        for pki_ca in pki_cascade.pki_cascade.values():
            pki_ca.setup()
        logging.debug(pki_cascade.pki_cascade_json(pretty=True))


    def test_pki_issue(self):
        pki_cascade = PKICascade(self.pki_cascade_configuration)
        for pki_ca in pki_cascade.pki_cascade.values():
            pki_ca.setup()
        for pki_ca in pki_cascade.pki_cascade.values():
            certificate = pki_ca.issue(subject_common_name='test', type=CertificateTypes.CLIENT, term=1)
            logging.debug(certificate.get_properties())

if __name__ == '__main__':
    unittest.main()
