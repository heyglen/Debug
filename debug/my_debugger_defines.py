import ctypes
from ctypes import wintypes
from typing import NamedTuple


# https://docs.microsoft.com/en-us/windows/desktop/api/WinBase/nf-winbase-formatmessage#parameters
class _FormatMessageFlags(NamedTuple):
    FORMAT_MESSAGE_ALLOCATE_BUFFER: int
    FORMAT_MESSAGE_FROM_SYSTEM: int
    FORMAT_MESSAGE_IGNORE_INSERTS: int


class Flags(NamedTuple):
    FormatMessage: _FormatMessageFlags


flags = Flags(
    FormatMessage=_FormatMessageFlags(
        FORMAT_MESSAGE_ALLOCATE_BUFFER=0x00000100,
        FORMAT_MESSAGE_FROM_SYSTEM=0x00001000,
        FORMAT_MESSAGE_IGNORE_INSERTS=0x00000200,
    ),
)


# https://docs.microsoft.com/en-us/windows/desktop/api/WinBase/nf-winbase-formatmessage
class _LanguageIdOption(NamedTuple):
    DEFAULT: int


class Options(NamedTuple):
    LanguageId: _LanguageIdOption


options = Options(
    LanguageId=_LanguageIdOption(
        DEFAULT=wintypes.DWORD(0),
    ),
)


class _DebugExceptionConstants(NamedTuple):
    EXCEPTION_ACCESS_VIOLATION: int
    EXCEPTION_BREAKPOINT: int
    EXCEPTION_GUARD_PAGE: int
    EXCEPTION_SINGLE_STEP: int


class _DebugEventConstants(NamedTuple):
    EXCEPTION_DEBUG_EVENT: int
    CREATE_THREAD_DEBUG_EVENT: int
    CREATE_PROCESS_DEBUG_EVENT: int
    EXIT_THREAD_DEBUG_EVENT: int
    EXIT_PROCESS_DEBUG_EVENT: int
    LOAD_DLL_DEBUG_EVENT: int
    UNLOAD_DLL_DEBUG_EVENT: int
    OUTPUT_DEBUG_STRING_EVENT: int
    RIP_EVENT: int


class _DebugContinueStatusConstants(NamedTuple):
    DEBUG_PROCESS: int
    CREATE_NEW_CONSOLE: int
    PROCESS_ALL_ACCESS: int
    INFINITE: int
    DBG_CONTINUE: int


class _DebugConstants(NamedTuple):
    event: _DebugEventConstants
    exception: _DebugExceptionConstants
    continue_status: _DebugContinueStatusConstants


class Constants(NamedTuple):
    debug: _DebugConstants


constant = Constants(
    debug=_DebugConstants(
        event=_DebugEventConstants(
            EXCEPTION_DEBUG_EVENT=0x1,
            CREATE_THREAD_DEBUG_EVENT=0x2,
            CREATE_PROCESS_DEBUG_EVENT=0x3,
            EXIT_THREAD_DEBUG_EVENT=0x4,
            EXIT_PROCESS_DEBUG_EVENT=0x5,
            LOAD_DLL_DEBUG_EVENT=0x6,
            UNLOAD_DLL_DEBUG_EVENT=0x7,
            OUTPUT_DEBUG_STRING_EVENT=0x8,
            RIP_EVENT=0x9,
        ),
        exception=_DebugExceptionConstants(
            EXCEPTION_ACCESS_VIOLATION=0xC0000005,
            EXCEPTION_BREAKPOINT=0x80000003,
            EXCEPTION_GUARD_PAGE=0x80000001,
            EXCEPTION_SINGLE_STEP=0x80000004,
        ),
        continue_status=_DebugContinueStatusConstants(
            DEBUG_PROCESS=0x00000001,
            CREATE_NEW_CONSOLE=0x00000010,
            PROCESS_ALL_ACCESS=0x001F0FFF,
            INFINITE=0xFFFFFFFF,
            DBG_CONTINUE=0x00010002,
        ),
    )
)

# Let's map the Microsoft types to ctypes for clarity
BYTE = ctypes.c_ubyte
WORD = ctypes.c_ushort
DWORD = ctypes.c_ulong
LPBYTE = ctypes.POINTER(ctypes.c_ubyte)
LPTSTR = ctypes.POINTER(ctypes.c_char)
HANDLE = ctypes.c_void_p
PVOID = ctypes.c_void_p
LPVOID = ctypes.c_void_p
UINT_PTR = ctypes.c_ulong
SIZE_T = ctypes.c_ulong


# Thread constants for CreateToolhelp32Snapshot()
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_INHERIT = 0x80000000
TH32CS_SNAPALL = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
THREAD_ALL_ACCESS = 0x001F03FF

# Context flags for GetThreadContext()
CONTEXT_FULL = 0x00010007
CONTEXT_DEBUG_REGISTERS = 0x00010010

# Memory permissions
PAGE_EXECUTE_READWRITE = 0x00000040

# Hardware breakpoint conditions
HW_ACCESS = 0x00000003
HW_EXECUTE = 0x00000000
HW_WRITE = 0x00000001

# Memory page permissions, used by VirtualProtect()
PAGE_NOACCESS = 0x00000001
PAGE_READONLY = 0x00000002
PAGE_READWRITE = 0x00000004
PAGE_WRITECOPY = 0x00000008
PAGE_EXECUTE = 0x00000010
PAGE_EXECUTE_READ = 0x00000020
PAGE_EXECUTE_READWRITE = 0x00000040
PAGE_EXECUTE_WRITECOPY = 0x00000080
PAGE_GUARD = 0x00000100
PAGE_NOCACHE = 0x00000200
PAGE_WRITECOMBINE = 0x00000400


# PROCESS_INFORMATION receives its information
# after the target process has been successfully
# started.

# When the dwDebugEventCode is evaluated


class EXCEPTION_RECORD(ctypes.Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ('ExceptionCode',        DWORD),
    ('ExceptionFlags',       DWORD),
    ('ExceptionRecord',      ctypes.POINTER(EXCEPTION_RECORD)),
    ('ExceptionAddress',     PVOID),
    ('NumberParameters',     DWORD),
    ('ExceptionInformation', UINT_PTR * 15),
]


class _EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ('ExceptionCode',        DWORD),
        ('ExceptionFlags',       DWORD),
        ('ExceptionRecord',      ctypes.POINTER(EXCEPTION_RECORD)),
        ('ExceptionAddress',     PVOID),
        ('NumberParameters',     DWORD),
        ('ExceptionInformation', UINT_PTR * 15),
    ]

# Exceptions


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ('ExceptionRecord',    EXCEPTION_RECORD),
        ('dwFirstChance',      DWORD),
    ]

# it populates this union appropriately


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

# DEBUG_EVENT describes a debugging event
# that the debugger has trapped


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ('dwDebugEventCode', DWORD),
        ('dwProcessId',      DWORD),
        ('dwThreadId',       DWORD),
        ('u',                DEBUG_EVENT_UNION),
    ]


class DebugStructure(NamedTuple):
    DEBUG_EVENT: DEBUG_EVENT


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess',    HANDLE),
        ('hThread',     HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId',  DWORD),
    ]


# STARTUPINFO describes how to spawn the process
# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/ns-processthreadsapi-startupinfow
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ('cb',            DWORD),
        ('lpReserved',    wintypes.LPWSTR),
        ('lpDesktop',     wintypes.LPWSTR),
        ('lpTitle',       wintypes.LPWSTR),
        ('dwX',           DWORD),
        ('dwY',           DWORD),
        ('dwXSize',       DWORD),
        ('dwYSize',       DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags',       DWORD),
        ('wShowWindow',   WORD),
        ('cbReserved2',   WORD),
        ('lpReserved2',   LPBYTE),
        ('hStdInput',     HANDLE),
        ('hStdOutput',    HANDLE),
        ('hStdError',     HANDLE),
    ]


class ProcessStructure(NamedTuple):
    PROCESS_INFORMATION: PROCESS_INFORMATION
    STARTUPINFOW: STARTUPINFOW


class Structure(NamedTuple):
    process: ProcessStructure
    debug: DebugStructure


structure = Structure(
    debug=DebugStructure(
        DEBUG_EVENT=DEBUG_EVENT,
    ),
    process=ProcessStructure(
        PROCESS_INFORMATION=PROCESS_INFORMATION,
        STARTUPINFOW=STARTUPINFOW,
    ),
)
# Used by the CONTEXT structure


class FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [

        ('ControlWord', DWORD),
        ('StatusWord', DWORD),
        ('TagWord', DWORD),
        ('ErrorOffset', DWORD),
        ('ErrorSelector', DWORD),
        ('DataOffset', DWORD),
        ('DataSelector', DWORD),
        ('RegisterArea', BYTE * 80),
        ('Cr0NpxState', DWORD),
    ]

# The CONTEXT structure which holds all of the
# register values after a GetThreadContext() call


class CONTEXT(ctypes.Structure):
    _fields_ = [

        ('ContextFlags', DWORD),
        ('Dr0', DWORD),
        ('Dr1', DWORD),
        ('Dr2', DWORD),
        ('Dr3', DWORD),
        ('Dr6', DWORD),
        ('Dr7', DWORD),
        ('FloatSave', FLOATING_SAVE_AREA),
        ('SegGs', DWORD),
        ('SegFs', DWORD),
        ('SegEs', DWORD),
        ('SegDs', DWORD),
        ('Edi', DWORD),
        ('Esi', DWORD),
        ('Ebx', DWORD),
        ('Edx', DWORD),
        ('Ecx', DWORD),
        ('Eax', DWORD),
        ('Ebp', DWORD),
        ('Eip', DWORD),
        ('SegCs', DWORD),
        ('EFlags', DWORD),
        ('Esp', DWORD),
        ('SegSs', DWORD),
        ('ExtendedRegisters', BYTE * 512),
    ]

# THREADENTRY32 contains information about a thread
# we use this for enumerating all of the system threads


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize',             DWORD),
        ('cntUsage',           DWORD),
        ('th32ThreadID',       DWORD),
        ('th32OwnerProcessID', DWORD),
        ('tpBasePri',          DWORD),
        ('tpDeltaPri',         DWORD),
        ('dwFlags',            DWORD),
    ]

# Supporting struct for the SYSTEM_INFO_UNION union


class PROC_STRUCT(ctypes.Structure):
    _fields_ = [
        ('wProcessorArchitecture',    WORD),
        ('wReserved',                 WORD),
    ]


# Supporting union for the SYSTEM_INFO struct
class SYSTEM_INFO_UNION(ctypes.Union):
    _fields_ = [
        ('dwOemId',    DWORD),
        ('sProcStruc', PROC_STRUCT),
    ]
# SYSTEM_INFO structure is populated when a call to
# kernel32.GetSystemInfo() is made. We use the dwPageSize
# member for size calculations when setting memory breakpoints


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ('uSysInfo', SYSTEM_INFO_UNION),
        ('dwPageSize', DWORD),
        ('lpMinimumApplicationAddress', LPVOID),
        ('lpMaximumApplicationAddress', LPVOID),
        ('dwActiveProcessorMask', DWORD),
        ('dwNumberOfProcessors', DWORD),
        ('dwProcessorType', DWORD),
        ('dwAllocationGranularity', DWORD),
        ('wProcessorLevel', WORD),
        ('wProcessorRevision', WORD),
    ]

# MEMORY_BASIC_INFORMATION contains information about a
# particular region of memory. A call to kernel32.VirtualQuery()
# populates this structure.


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', PVOID),
        ('AllocationBase', PVOID),
        ('AllocationProtect', DWORD),
        ('RegionSize', SIZE_T),
        ('State', DWORD),
        ('Protect', DWORD),
        ('Type', DWORD),
    ]
