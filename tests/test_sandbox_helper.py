from unittest import TestCase

from secimport import secure_import

class TestPySandbox(TestCase):
    def test_import_with_shell_true(self):
        secure_import('urllib', open_shells=True)
        a = [_**9 for _ in range(100)]
        print(a)
            
    
    def test_import_with_shell_false(self):
        module = secure_import('this', open_shells=False)
        self.assertEqual(module.__name__, 'this')