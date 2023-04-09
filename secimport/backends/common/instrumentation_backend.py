from enum import Enum


class InstrumentationBackend(Enum):
    DTRACE = "dtrace"
    EBPF = "ebpf"  # bpftrace
