from unittest import TestCase

from secimport import secure_import

class TestPySandbox(TestCase):
    def test_import_with_shell_true(self):
        secure_import('urllib')
        a = [_**9 for _ in range(100)]
        print(a)
            
    
    def test_import_with_shell_false(self):
        module = secure_import('this')
        self.assertEqual(module.__name__, 'this')