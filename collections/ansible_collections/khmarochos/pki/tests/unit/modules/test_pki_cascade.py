import unittest
import yaml
import q
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.khmarochos.pki.plugins.module_utils.pki_cascade import PKICascade


class InitCascadeTest(unittest.TestCase):

    def setUp(self):
        with open("test-case-full.yaml", "r") as stream:
            self.pki_ca_cascade_configuration = (yaml.safe_load(stream))["pki_ca_cascade"]

    def test_initialisation(self):
        pki_ca_cascade = PKICascade(self.pki_ca_cascade_configuration)
        self.assertTrue(type(pki_ca_cascade), PKICascade)

    def test_setup(self):
        pki_cascade = PKICascade(self.pki_ca_cascade_configuration)
        for pki_ca in pki_cascade.pki_cascade.values():
            pki_ca.setup()


if __name__ == '__main__':
    unittest.main()
