import unittest
from ansible.module_utils.basic import AnsibleModule

from ansible_collections.khmarochos.pki.plugins.modules import init_dictionary


class InitCascadeTest(unittest.TestCase):

    def test_initialisation(self):


        init_dictionary.main()


if __name__ == '__main__':
    unittest.main()