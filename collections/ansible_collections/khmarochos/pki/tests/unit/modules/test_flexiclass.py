import unittest

from ansible_collections.khmarochos.pki.plugins.module_utils.flexiclass import FlexiClass


class Persistence(unittest.TestCase):
    class Foo(FlexiClass, properties={
        FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
            'type': str,
            'mandatory': True,
            'readonly': False
        },
        'alpha': {},
        'bravo': {},
        'charlie': {}
    }):
        pass

    def test_something(self):
        foo1 = Persistence.Foo(alpha='foo1-alpha', bravo='foo1-bravo', charlie='foo1-charlie')
        self.assertEqual('foo1-alpha', foo1.alpha)
        self.assertEqual('foo1-bravo', foo1.bravo)
        self.assertEqual('foo1-charlie', foo1.charlie)
        foo2 = Persistence.Foo(alpha='foo2-alpha', bravo='foo2-bravo', charlie='foo2-charlie')
        self.assertEqual('foo1-alpha', foo1.alpha)
        self.assertEqual('foo1-bravo', foo1.bravo)
        self.assertEqual('foo1-charlie', foo1.charlie)
        self.assertEqual('foo2-alpha', foo2.alpha)
        self.assertEqual('foo2-bravo', foo2.bravo)
        self.assertEqual('foo2-charlie', foo2.charlie)
        foo3 = Persistence.Foo(alpha='foo3-alpha', bravo='foo3-bravo', charlie='foo3-charlie')
        self.assertEqual('foo1-alpha', foo1.alpha)
        self.assertEqual('foo1-bravo', foo1.bravo)
        self.assertEqual('foo1-charlie', foo1.charlie)
        self.assertEqual('foo2-alpha', foo2.alpha)
        self.assertEqual('foo2-bravo', foo2.bravo)
        self.assertEqual('foo2-charlie', foo2.charlie)
        self.assertEqual('foo3-alpha', foo3.alpha)
        self.assertEqual('foo3-bravo', foo3.bravo)
        self.assertEqual('foo3-charlie', foo3.charlie)
        foo3.alpha = 'foo3-alpha-modified'
        foo3.bravo = 'foo3-bravo-modified'
        foo3.charlie = 'foo3-charlie-modified'
        self.assertEqual('foo1-alpha', foo1.alpha)
        self.assertEqual('foo1-bravo', foo1.bravo)
        self.assertEqual('foo1-charlie', foo1.charlie)
        self.assertEqual('foo2-alpha', foo2.alpha)
        self.assertEqual('foo2-bravo', foo2.bravo)
        self.assertEqual('foo2-charlie', foo2.charlie)
        self.assertEqual('foo3-alpha-modified', foo3.alpha)
        self.assertEqual('foo3-bravo-modified', foo3.bravo)
        self.assertEqual('foo3-charlie-modified', foo3.charlie)


class PropertyBinding(unittest.TestCase):

    class Charlie(FlexiClass, properties={
        FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
            'type': str,
            'mandatory': True,
            'readonly': False
        },
        'value': {'type': int, 'readonly': False}
    }):
        pass

    class Bravo(FlexiClass, properties={
        FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
            'type': str,
            'mandatory': True,
            'readonly': False
        },
        'charlie': {'type': Charlie, 'readonly': False, 'mandatory': False},
        'charlie_value': {'type': int, 'readonly': True}
    }):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.charlie = PropertyBinding.Charlie(value=self.charlie_value)
            self._bind_properties([{'object': self.charlie, 'properties': {'value': 'charlie_value'}}])

    class Alpha(FlexiClass, properties={
        FlexiClass.DEFAULT_PROPERTY_SETTINGS_KEY: {
            'type': str,
            'mandatory': True,
            'readonly': False
        },
        'bravo': {'type': Bravo, 'readonly': False, 'mandatory': False},
        'charlie_value': {'type': int, 'readonly': True}
    }):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.bravo = PropertyBinding.Bravo(charlie_value=self.charlie_value)
            self._bind_properties([{'object': self.bravo.charlie, 'properties': {'value': 'charlie_value'}}])

    def test_property_binding(self):
        alpha = PropertyBinding.Alpha(charlie_value=42)
        self.assertEqual(alpha.charlie_value, 42)
        self.assertEqual(alpha.bravo.charlie_value, 42)
        self.assertEqual(alpha.bravo.charlie.value, 42)
        alpha.bravo.charlie.value = 13
        self.assertEqual(alpha.charlie_value, 13)
        self.assertEqual(alpha.bravo.charlie_value, 13)
        self.assertEqual(alpha.bravo.charlie.value)

    def test_property_binding_with_new_object(self):
        alpha_foo = PropertyBinding.Alpha(charlie_value=13)
        self.assertEqual(13, alpha_foo.charlie_value)
        alpha_foo = PropertyBinding.Alpha(charlie_value=42)
        self.assertEqual(42, alpha_foo.charlie_value)

if __name__ == '__main__':
    unittest.main(42)
