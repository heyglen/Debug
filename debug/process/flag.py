from typing import NamedTuple


class _TH32CSFlags(NamedTuple):
    TH32CS_SNAPHEAPLIST: int
    TH32CS_SNAPPROCESS: int
    TH32CS_SNAPTHREAD: int
    TH32CS_SNAPMODULE: int
    TH32CS_INHERIT: int
    TH32CS_SNAPALL: int
    THREAD_ALL_ACCESS: int


class _ThreadContextFlag(NamedTuple):
    CONTEXT_FULL: int
    CONTEXT_DEBUG_REGISTERS: int


class _ThreadFlag(NamedTuple):
    th32cs: _TH32CSFlags
    context: _ThreadContextFlag


class _Flag(NamedTuple):
    thread: _ThreadFlag


flag = _Flag(
    thread=_ThreadFlag(
        th32cs=_TH32CSFlags(
            TH32CS_SNAPHEAPLIST=0x00000001,
            TH32CS_SNAPPROCESS=0x00000002,
            TH32CS_SNAPTHREAD=0x00000004,
            TH32CS_SNAPMODULE=0x00000008,
            TH32CS_INHERIT=0x80000000,
            # TH32CS_SNAPALL=(TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
            TH32CS_SNAPALL=(0x00000001 | 0x00000002 | 0x00000004 | 0x00000008),
            THREAD_ALL_ACCESS=0x001F03FF,
        ),
        context=_ThreadContextFlag(
            CONTEXT_FULL=0x00010007,
            CONTEXT_DEBUG_REGISTERS=0x00010010,
        ),
    ),
)
