import ctypes
from ctypes import wintypes


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

# Used by the CONTEXT structure


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
