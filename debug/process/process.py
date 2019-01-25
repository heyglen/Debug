
import ctypes
from ctypes import wintypes
import logging

from .memory import ProcessMemory
from .structure import structure
from .constant import constant
from .process_thread import ProcessThreads
from ..kernel32 import kernel32

logger = logging.getLogger('debugger.process')


class Process:

    def __init__(self, process_id):
        self.id_ = process_id
        self._process_handle = None
        self._image_file_name = None
        self.memory = ProcessMemory(self.handle)

        self.threads = ProcessThreads(self)

    @classmethod
    def create(cls, path_to_exe):
        logger.debug('Create process [kernel32.CreateProcessW]')
        creation_flags = constant.debug.continue_status.DEBUG_PROCESS
        creation_flags = constant.debug.continue_status.CREATE_NEW_CONSOLE
        startup_info = structure.process.STARTUPINFOW()
        process_information = structure.process.PROCESS_INFORMATION()

        # The following two options allow the started process to be shown as a
        # seperate window. This also illustrates
        # how different settings in the STARTUPINFO struct can affect the
        # debuggee.

        startup_info.dwFlags = 0x1
        startup_info.wShowWindow = 0x0

        # We then initialize the cb variable in the STARTUPINFO struct
        # which is just the size of the struct itself
        startup_info.cb = ctypes.sizeof(startup_info)

        # https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createprocessw
        CreateProcessW = kernel32.CreateProcessW

        CreateProcessW.argtypes = [
            wintypes.LPCWSTR,                # lpApplicationName
            wintypes.LPWSTR,                 # lpCommandLine
            wintypes.LPSECURITY_ATTRIBUTES,  # lpProcessAttributes
            wintypes.LPSECURITY_ATTRIBUTES,  # lpThreadAttributes
            wintypes.BOOL,                   # bInheritHandles
            wintypes.DWORD,                  # dwCreationFlags
            wintypes.LPVOID,                 # lpEnvironment
            wintypes.LPCWSTR,                # lpCurrentDirectory
            wintypes.LPSTARTUPINFOW,         # lpStartupInfo
            wintypes.LPPROCESS_INFORMATION,  # lpProcessInformation
        ]
        CreateProcessW.restype = wintypes.BOOL

        system_error_code = CreateProcessW(
            path_to_exe,                        # lpApplicationName
            None,                               # lpCommandLine
            None,                               # lpProcessAttributes
            None,                               # lpThreadAttributes
            None,                               # bInheritHandles
            creation_flags,                     # dwCreationFlags
            None,                               # lpEnvironment
            None,                               # lpCurrentDirectory
            ctypes.byref(startup_info),         # lpStartupInfo
            ctypes.byref(process_information),  # lpProcessInformation
        )

        if system_error_code:
            logger.error('CreateProcessW')
            raise ctypes.WinError()
        process_id = int(process_information.dwProcessId)
        debugger = cls(process_id)
        # logger.debug(f'[*] Return Code {result}')
        # logger.debug('[*] We have successfully launched the process')
        # logger.debug(f'[*] PID {self.process_id}')
        return debugger

    @property
    def handle(self):
        logger.debug('Get process handle [kernel32.OpenProcess]')
        if self._process_handle is not None:
            return self._process_handle
        OpenProcess = kernel32.OpenProcess

        OpenProcess.argtypes = [
            wintypes.DWORD,                  # dwDesiredAccess
            wintypes.BOOL,                   # bInheritHandle
            wintypes.DWORD,                  # dwProcessId
        ]
        OpenProcess.restype = wintypes.HANDLE

        process_handle = OpenProcess(
            constant.debug.continue_status.PROCESS_ALL_ACCESS,                 # DWORD dwDesiredAccess
            False,                                                             # BOOL  bInheritHandle
            wintypes.DWORD(self.id_),                                        # DWORD dwProcessId
        )
        self._process_handle = process_handle

        return self._process_handle

    @property
    def name(self):
        logger.debug('Get process image name [windll.psapi.GetProcessImageFileNameW]')
        if self._image_file_name is not None:
            return self._image_file_name

        if not self._process_handle:
            self._process_handle = self.get_handle()

        GetProcessImageFileNameW = ctypes.windll.psapi.GetProcessImageFileNameW

        # https://docs.microsoft.com/en-us/windows/desktop/api/psapi/nf-psapi-getprocessimagefilenamew
        GetProcessImageFileNameW.argtypes = [
            wintypes.HANDLE,              # hProcess
            wintypes.LPWSTR,              # lpImageFileName
            wintypes.DWORD,               # nSize
        ]
        # The length of the string copied to the buffer
        GetProcessImageFileNameW.restype = wintypes.DWORD

        image_file_name = ctypes.create_unicode_buffer(wintypes.MAX_PATH)

        string_buffer_length = GetProcessImageFileNameW(
            self._process_handle,
            image_file_name,
            wintypes.DWORD(wintypes.MAX_PATH),
        )

        if string_buffer_length == 0:
            logger.error('GetProcessImageFileNameW')
            raise ctypes.WinError()

        self._image_file_name = image_file_name.value
        return self._image_file_name
