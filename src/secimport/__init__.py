from secimport.sandbox_helper import secure_import
imports = secure_import
from secimport.backends.common.utils import build_module_sandbox_from_yaml_template as generate_sandbox_from_yaml
__all__ = ["imports", "secure_import", "generate_sandbox_from_yaml"]

if __name__ == '__main__':
    import fire
    fire.Fire(generate_sandbox_from_yaml)
