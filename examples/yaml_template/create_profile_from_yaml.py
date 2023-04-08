from pathlib import Path
import sys
from secimport.backends.common.instrumentation_backend import InstrumentationBackend

from secimport.backends.common.utils import build_module_sandbox_from_yaml_template


def main():
    template_filename = Path(sys.argv[1])
    dtrace_sandbox_filename = Path(sys.argv[2]).with_suffix(".d")

    dtrace_rendered_profile = build_module_sandbox_from_yaml_template(
        template_path=template_filename, backend=InstrumentationBackend.DTRACE
    )
    with open(dtrace_sandbox_filename, "w") as f:
        f.write(dtrace_rendered_profile)

    bpftrace_sandbox_filename = Path(sys.argv[2]).with_suffix(".bt")
    bpftrace_rendered_profile = build_module_sandbox_from_yaml_template(
        template_path=template_filename, backend=InstrumentationBackend.EBPF
    )
    with open(bpftrace_sandbox_filename, "w") as f:
        f.write(bpftrace_rendered_profile)

    print("\nDTRACE SANDBOX: ", dtrace_sandbox_filename)
    print("BPFTRCE SANDBOX: ", bpftrace_sandbox_filename)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise ValueError(
            "Please provide 2 command-line arguments:\n\tcreate_profile_from_yaml.py <template_filename> <sandbox_file_name>"
        )
    main()
