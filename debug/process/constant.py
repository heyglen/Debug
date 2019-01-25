import ctypes
from ctypes import wintypes
from typing import NamedTuple


class _DebugContinueStatusConstants(NamedTuple):
    DEBUG_PROCESS: int
    CREATE_NEW_CONSOLE: int
    PROCESS_ALL_ACCESS: int
    INFINITE: int
    DBG_CONTINUE: int


class _DebugConstants(NamedTuple):
    continue_status: _DebugContinueStatusConstants


class _Handle(NamedTuple):
    INVALID_HANDLE_VALUE: int


class Constants(NamedTuple):
    debug: _DebugConstants
    handle: _Handle

constant = Constants(
    debug=_DebugConstants(
        continue_status=_DebugContinueStatusConstants(
            DEBUG_PROCESS=0x00000001,
            CREATE_NEW_CONSOLE=0x00000010,
            PROCESS_ALL_ACCESS=0x001F0FFF,
            INFINITE=0xFFFFFFFF,
            DBG_CONTINUE=0x00010002,
        ),
    ),
    handle=_Handle(
        INVALID_HANDLE_VALUE=wintypes.DWORD(-1).value
    )
)
