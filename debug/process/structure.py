import ctypes
from ctypes import wintypes
from typing import NamedTuple


class EXCEPTION_RECORD(ctypes.Structure):
    pass


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ('ExceptionRecord',    EXCEPTION_RECORD),
        ('dwFirstChance',      wintypes.DWORD),
    ]


class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ('Exception',         EXCEPTION_DEBUG_INFO),
        #        ('CreateThread',      CREATE_THREAD_DEBUG_INFO),
        #        ('CreateProcessInfo', CREATE_PROCESS_DEBUG_INFO),
        #        ('ExitThread',        EXIT_THREAD_DEBUG_INFO),
        #        ('ExitProcess',       EXIT_PROCESS_DEBUG_INFO),
        #        ('LoadDll',           LOAD_DLL_DEBUG_INFO),
        #        ('UnloadDll',         UNLOAD_DLL_DEBUG_INFO),
        #        ('DebugString',       OUTPUT_DEBUG_STRING_INFO),
        #        ('RipInfo',           RIP_INFO),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ('dwDebugEventCode', wintypes.DWORD),
        ('dwProcessId',      wintypes.DWORD),
        ('dwThreadId',       wintypes.DWORD),
        ('u',                DEBUG_EVENT_UNION),
    ]


class DebugStructure(NamedTuple):
    DEBUG_EVENT: DEBUG_EVENT


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess',    wintypes.HANDLE),
        ('hThread',     wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId',  wintypes.DWORD),
    ]


# STARTUPINFO describes how to spawn the process
# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/ns-processthreadsapi-startupinfow
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ('cb',            wintypes.DWORD),
        ('lpReserved',    wintypes.LPWSTR),
        ('lpDesktop',     wintypes.LPWSTR),
        ('lpTitle',       wintypes.LPWSTR),
        ('dwX',           wintypes.DWORD),
        ('dwY',           wintypes.DWORD),
        ('dwXSize',       wintypes.DWORD),
        ('dwYSize',       wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags',       wintypes.DWORD),
        ('wShowWindow',   wintypes.WORD),
        ('cbReserved2',   wintypes.WORD),
        ('lpReserved2',   wintypes.LPBYTE),
        ('hStdInput',     wintypes.HANDLE),
        ('hStdOutput',    wintypes.HANDLE),
        ('hStdError',     wintypes.HANDLE),
    ]


class ProcessStructure(NamedTuple):
    PROCESS_INFORMATION: PROCESS_INFORMATION
    STARTUPINFOW: STARTUPINFOW


# THREADENTRY32 contains information about a thread
# we use this for enumerating all of the system threads

class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize',             wintypes.DWORD),
        ('cntUsage',           wintypes.DWORD),
        ('th32ThreadID',       wintypes.DWORD),
        ('th32OwnerProcessID', wintypes.DWORD),
        ('tpBasePri',          wintypes.DWORD),
        ('tpDeltaPri',         wintypes.DWORD),
        ('dwFlags',            wintypes.DWORD),
    ]


class FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [

        ('ControlWord', wintypes.DWORD),
        ('StatusWord', wintypes.DWORD),
        ('TagWord', wintypes.DWORD),
        ('ErrorOffset', wintypes.DWORD),
        ('ErrorSelector', wintypes.DWORD),
        ('DataOffset', wintypes.DWORD),
        ('DataSelector', wintypes.DWORD),
        ('RegisterArea', wintypes.BYTE * 80),
        ('Cr0NpxState', wintypes.DWORD),
    ]


class CONTEXT(ctypes.Structure):
    _fields_ = [

        ('ContextFlags', wintypes.DWORD),
        ('Dr0', wintypes.DWORD),
        ('Dr1', wintypes.DWORD),
        ('Dr2', wintypes.DWORD),
        ('Dr3', wintypes.DWORD),
        ('Dr6', wintypes.DWORD),
        ('Dr7', wintypes.DWORD),
        ('FloatSave', FLOATING_SAVE_AREA),
        ('SegGs', wintypes.DWORD),
        ('SegFs', wintypes.DWORD),
        ('SegEs', wintypes.DWORD),
        ('SegDs', wintypes.DWORD),
        ('Edi', wintypes.DWORD),
        ('Esi', wintypes.DWORD),
        ('Ebx', wintypes.DWORD),
        ('Edx', wintypes.DWORD),
        ('Ecx', wintypes.DWORD),
        ('Eax', wintypes.DWORD),
        ('Ebp', wintypes.DWORD),
        ('Eip', wintypes.DWORD),
        ('SegCs', wintypes.DWORD),
        ('EFlags', wintypes.DWORD),
        ('Esp', wintypes.DWORD),
        ('SegSs', wintypes.DWORD),
        ('ExtendedRegisters', wintypes.BYTE * 512),
    ]


class ThreadStructure(NamedTuple):
    THREADENTRY32: THREADENTRY32
    CONTEXT: CONTEXT


class Structure(NamedTuple):
    process: ProcessStructure
    debug: DebugStructure
    thread: ThreadStructure


structure = Structure(
    debug=DebugStructure(
        DEBUG_EVENT=DEBUG_EVENT,
    ),
    thread=ThreadStructure(
        THREADENTRY32=THREADENTRY32,
        CONTEXT=CONTEXT,
    ),
    process=ProcessStructure(
        PROCESS_INFORMATION=PROCESS_INFORMATION,
        STARTUPINFOW=STARTUPINFOW,
    ),
)
