import unittest
from secimport.backends.bpftrace_backend.bpftrace_backend import (
    run_bpftrace_script_for_module,
    create_bpftrace_script_for_module,
    render_allowlist_template,
    render_blocklist_template,
    render_bpftrace_template,
    render_bpftrace_probe_for_module,
)


class TestEBPFBackend(unittest.TestCase):
    def test_run_bpftrace_script_for_module(self):
        # run_bpftrace_script_for_module
        # TODO: implement
        self.fail()

    def test_create_bpftrace_script_for_module(self):
        # create_bpftrace_script_for_module
        # TODO: implement
        self.fail()

    def test_render_allowlist_template(self):
        # render_allowlist_template
        # TODO: implement
        self.fail()

    def test_render_blocklist_template(self):
        # render_blocklist_template
        # TODO: implement
        self.fail()

    def test_render_bpftrace_template(self):
        # render_bpftrace_template
        # TODO: implement
        self.fail()

    def test_render_bpftrace_probe_for_module(self):
        # render_bpftrace_probe_for_module
        # TODO: implement
        self.fail()


if __name__ == "__main__":
    unittest.main()
