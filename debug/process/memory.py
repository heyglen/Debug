import ctypes
from ctypes import wintypes
import logging


logger = logging.getLogger('debugger.process.memory')

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)


class ProcessMemory:

    def __init__(self, process_handle):
        self._process_handle = process_handle

    def read(self, address, length=None):
        data = b''
        read_buffer = ctypes.create_string_buffer(length)
        count = ctypes.c_size_t(0)
        size = length if length is not None else ctypes.sizeof(data)

        ReadProcessMemory = kernel32.ReadProcessMemory
        ReadProcessMemory.argtypes = [
            wintypes.HANDLE,                   # hProcess
            wintypes.LPCVOID,                  # lpBaseAddress
            wintypes.LPVOID,                   # lpBuffer
            ctypes.c_size_t,                   # nSize
            ctypes.POINTER(ctypes.c_size_t),   # *lpNumberOfBytesWritten
        ]
        ReadProcessMemory.restype = wintypes.BOOL

        system_error_code = ReadProcessMemory(
            self._process_handle,    # hProcess
            address,                # lpBaseAddress
            read_buffer,            # lpBuffer
            size,                   # nSize
            ctypes.byref(count),    # *lpNumberOfBytesWritten
        )
        if system_error_code:
            logger.error('ReadProcessMemory')
            raise ctypes.WinError()
        return read_buffer.raw

    def write(self, address, data):
        count = ctypes.c_size_t(0)
        length = len(data)
        c_data = ctypes.c_char_p(data[count.value:])

        WriteProcessMemory = kernel32.WriteProcessMemory
        WriteProcessMemory.argtypes = [
            wintypes.HANDLE,                   # hProcess
            wintypes.LPVOID,                   # lpBaseAddress
            wintypes.LPCVOID,                  # lpBuffer
            ctypes.c_size_t,                   # nSize
            ctypes.POINTER(ctypes.c_size_t),   # *lpNumberOfBytesWritten
        ]
        WriteProcessMemory.restype = wintypes.BOOL

        system_error_code = kernel32.WriteProcessMemory(
            self._process_handle,
            address,
            c_data,
            length,
            ctypes.byref(count),
        )
        if system_error_code:
            logger.error('WriteProcessMemory')
            raise ctypes.WinError()

        return bool(system_error_code)
