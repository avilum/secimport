from secimport import secure_import

# 'secure_import' don't interfere with other modules. os should work.
import os

malicious = secure_import("malicious")

if __name__ == "__main__":
    os.system(
        'echo "\nHello from os.system!\n Now we will try to execute the malicious module under supervision..."'
    )
    malicious.malicious()
