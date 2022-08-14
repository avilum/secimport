# YAML Profiles and Templates
It is very convenient to specify all of you policies, for all of your 3rd party apps and open source apps, in a single YAML file. 

# Create a custom sandbox
1. Generate a profile for your application using dtrace
2. Save the YAML output of step 1 into a file
3. Build a sandbox (dtrace script) from the yaml file
1. Run your app in your sandbox!

## 1. Generate a profile for your application
```shell
dtrace2) ➜  secimport git:(master) ✗ sudo dtrace -s src/secimport/templates/generate_profile.d -c "python -m http.server"

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

An example for a template is available in <a href="../src/secimport/profiles/example.yaml">example.yaml</a>.

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
python examples/create_profile_from_yaml.py src/secimport/profiles/example.yaml /tmp/example.d
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
