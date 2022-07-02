from secimport import secure_import

# Should not do anything as nothing is executed in the forbodden module.
import os


# Secure import without shells:
#   import malicious
malicious = secure_import("malicious")

if __name__ == "__main__":
    os.system('echo "Hello from os.system! Now we will try to execute the malicious module under supervision..."')
    malicious.malicious()
    print("ERROR - The process should have been killed and not print this log.")
