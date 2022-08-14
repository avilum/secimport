from secimport.sandbox_helper import build_module_sandbox_from_yaml_template
from pathlib import Path
import sys


def main():
    template_filename = Path(sys.argv[1])
    rendered_profile_filename = Path(sys.argv[2])
    rendered_profile = build_module_sandbox_from_yaml_template(
        template_path=template_filename
    )
    with open(rendered_profile_filename, "w") as f:
        f.write(rendered_profile)
        print("Done! The sandbox profile is ready at ", rendered_profile_filename)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise ValueError(
            "Please provide 2 command-line arguments:\n\tcreate_profile_from_yaml.py <template_filename> <rendered_profile_filename>"
        )
    main()
