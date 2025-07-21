import logging
import sys
import unittest

from ansible_collections.khmarochos.pki.plugins.module_utils.flexibuilder import FlexiBuilder
from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler(sys.stdout)])


class BuilderTest(unittest.TestCase):
    class Foo(FlexiClass, properties={
        FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
            'type': str,
            'mandatory': True,
            'readonly': False
        },
        'alpha': {},
        'bravo': {},
        'charlie': {'mandatory': False}
    }):
        pass

    class FooBuilder(FlexiBuilder, properties={
        FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
            'type': str,
            'mandatory': False,
            'readonly': False,
            'add_builder_updater': True
        },
        'alpha': {},
        'bravo': {},
        'charlie': {}
    }):

        def build(self):
            return BuilderTest.Foo(alpha=self.alpha, bravo=self.bravo, charlie=self.charlie)

    def test_something(self):
        builder = BuilderTest.FooBuilder()
        builder.add_alpha('foo1-alpha').add_bravo('foo1-bravo').build()
        logging.debug(builder.__dict__)
