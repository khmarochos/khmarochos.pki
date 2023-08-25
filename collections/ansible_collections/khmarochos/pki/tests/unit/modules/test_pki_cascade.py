import unittest
import yaml

from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade import PKICascade


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
        pki_cascade.pki_cascade_json()


if __name__ == '__main__':
    unittest.main()
