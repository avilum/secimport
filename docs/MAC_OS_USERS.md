<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Mac users](#mac-users)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Mac users
To use dtrace and to access moduels names in the kernel, you should disable SIP (System Integrity Protection) for dtrace. You can disable it for dtrace only:
  - boot into recovery mode using `command + R`.
  -  When recovery mode screen is show, open Utilities -> Terminal
  - `csrutil disable`
  - `csrutil enable --without dtrace`
