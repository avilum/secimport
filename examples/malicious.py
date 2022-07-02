"""An example module that uses os.system for shell spawning, executing 5 commands.
"""

import os, time, random


def malicious():
    pid = os.getpid()
    print('(python user space): Hello World! PID={pid}'.format(pid=pid))
    print('(python user space): Doing some chaos...')
    commands = ['ps', 'echo Hello', 'head -n 5 /etc/passwd', 'echo "example payload..." > /tmp/hi.txt']
    random.shuffle(commands)
    print('(python user space): Running random commands from the following set:\r\n', '\t-' + f'{os.linesep}\t-'.join(commands))
    for _ in commands:
        print(f"(python user space): Opening shell to execute: '{_}'")
        os.system(_)

if __name__ == '__main__':
    malicious()
