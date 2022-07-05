## Mac users
To use dtrace and to access moduels names in the kernel, you should disable SIP (System Integrity Protection) for dtrace. You can disable it for dtrace only:
  - boot into recovery mode using `command + R`.
  -  When recovery mode screen is show, open Utilities -> Terminal
  - `csrutil disable`
  - `csrutil enable --without dtrace` 