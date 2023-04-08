<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [YAML Profiles and Templates](#yaml-profiles-and-templates)
- [Create a custom sandbox](#create-a-custom-sandbox)
  - [1. Generate a profile for your application](#1-generate-a-profile-for-your-application)
  - [2. Save the YAML output](#2-save-the-yaml-output)
  - [3. Build a sandbox (dtrace script) from a yaml file](#3-build-a-sandbox-dtrace-script-from-a-yaml-file)
  - [4. Run your app in your sandbox](#4-run-your-app-in-your-sandbox)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# YAML Profiles and Templates
It is very convenient to specify all of you policies, for all of your 3rd party and open source modules, in a single YAML file.

# Create a custom sandbox
1. Generate a profile for your application using the tracing script.
2. Create a YAML security profile from your trace.
3. Build a sandbox (dtrace script) from the yaml file
1. Run your app in your sandbox!

## 1. Generate a profile for your application
```shell
dtrace2) ➜  secimport git:(master) ✗ sudo dtrace -s secimport/templates/generate_profile.d -c "python -m http.server"

Serving HTTP on :: port 8000 (http://[::]:8000/) ...

CTRL + C


 Generated syscalls (yaml profile):
    destructive: true
    syscall_allowlist:
        - __mac_syscall
        - __pthread_canceled
        - bind
        - csrctl
        - fgetattrlist
...
        - read
        - ioctl
        - stat64

Done.
```

##  2. Save the YAML output
 After yout hit CTRL + C, after "Generated syscalls (yaml profile)", the YAML profile is printed.

An example for a template is available in <a href="../secimport/profiles/example.yaml">example.yaml</a>.

 It should look like this:
```shell
# Example yaml file (with example syscalls)

modules:
  requests:
    destructive: true
    syscall_allowlist:
      - write
      - ioctl
      - stat64
  fastapi:
    destructive: true
    syscall_allowlist:
      - bind
      - fchmod
      - stat64
  uvicorn:
    destructive: true
    syscall_allowlist:
      - getpeername
      - getpgrp
      - stat64
```

 Save the output of dtrace into a local YAML file and proceed to step 3.

## 3. Build a sandbox (dtrace script) from a yaml file
Usage:<br>
```shell
python examples/create_profile_from_yaml.py <yaml_template_filename> <sandbox_target_filename>
```
Example:
```shell
python examples/create_profile_from_yaml.py secimport/profiles/example.yaml /tmp/example.d
```

Or, use the python API:
```python
import secimport, pathlib

template_path = pathlib.Path(secimport.sandbox_helper.PROFILES_DIR_NAME / 'example.yaml')

sandbox_code = secimport.sandbox_helper.build_module_sandbox_from_yaml_template(template_path)
```


## 4. Run your app in your sandbox
```shell
sudo dtrace -s /tmp/example.d -c "python"
```

And that's it!
