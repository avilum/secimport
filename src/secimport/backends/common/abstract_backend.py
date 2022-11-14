"""
An abstract backend for language runtime instrumentation.
Copyright (c) 2022 Avi Lumelsky
"""

from abc import ABC
from sys import executable as PYTHON_EXECUTABLE
from pathlib import Path
from typing import List

from secimport.backends.common.instrumentation_backend import InstrumentationBackend
from secimport.backends.common.utils import TEMPLATES_DIR_NAME


class SandboxInstrumentationBackend(ABC):
    @property
    def name(self):
        # return "bpftrace"
        raise NotImplementedError()

    @property
    def backend(self):
        # return InstrumentationBackend.EBPF
        raise NotImplementedError()

    @staticmethod
    def run_script_for_module(
        module_name: str,
        allow_shells: bool,
        allow_networking: bool,
        log_python_calls: bool,
        log_syscalls: bool,
        log_network: bool,
        log_file_system: bool,
        destructive: bool,
        syscalls_allowlist: List[str],
        syscalls_blocklist: List[str],
        use_sudo: bool = False,
        templates_dir: Path = TEMPLATES_DIR_NAME,
    ):
        raise NotImplementedError()

    @staticmethod
    def create_script_for_module(
        module_name: str,
        allow_shells: bool,
        allow_networking: bool,
        log_python_calls: bool,
        log_syscalls: bool,
        log_network: bool,
        log_file_system: bool,
        destructive: bool,
        syscalls_allowlist: List[str] = None,
        syscalls_blocklist: List[str] = None,
        templates_dir: Path = TEMPLATES_DIR_NAME,
    ) -> Path:
        raise NotImplementedError()

    @staticmethod
    def render_bpftrace_template(
        module_traced_name: str,
        allow_shells: bool,
        allow_networking: bool,
        log_python_calls: bool,
        log_syscalls: bool,
        log_network: bool,
        log_file_system: bool,
        destructive: bool,
        templates_dir: Path = TEMPLATES_DIR_NAME,
        default_template_filename: str = "default.template.example",
        interpreter_path: str = PYTHON_EXECUTABLE,
    ):
        raise NotImplementedError()

    @staticmethod
    def render_allowlist_template(
        module_name: str,
        destructive: bool,
        syscalls_allowlist: List[str],
        templates_dir: Path = TEMPLATES_DIR_NAME,
    ):
        raise NotImplementedError()

    @staticmethod
    def render_blocklist_template(
        module_name: str,
        destructive: bool,
        syscalls_blocklist: List[str],
        templates_dir: Path = TEMPLATES_DIR_NAME,
    ):
        raise NotImplementedError()

    @staticmethod
    def render_instrumentation_for_module(
        module_name: str,
        destructive: bool,
        syscalls_list: List[str],
        syscalls_allow: bool,
        templates_dir: Path = TEMPLATES_DIR_NAME,
        interpreter_path: str = PYTHON_EXECUTABLE,
    ) -> str:
        raise NotImplementedError()
