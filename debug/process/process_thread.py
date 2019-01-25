import contextlib
import ctypes

from ctypes import wintypes
import logging

from debug.kernel32 import kernel32
from .handle_resource import HandleResource
from .structure import structure
# from .constant import constant
from .flag import flag
# from .flag import flag
from .snapshot import Snapshot


logger = logging.getLogger('debugger.process.thread')


class ProcessThread(HandleResource):
    def __init__(self):
        self.process_id = None
        self.id_ = None
        self.priority = None
        self._handle = None

    @contextlib.contextmanager
    def handle(self):
        thread_handle = self._open()
        yield thread_handle
        self.close(thread_handle)

    def _open(self):
        logger.debug(f'Open thread [kernel32.OpenThread]')
        OpenThread = kernel32.OpenThread
        OpenThread.argtypes = [
            wintypes.DWORD,  # dwDesiredAccess
            wintypes.BOOL,   # bInheritHandle
            wintypes.DWORD,  # dwThreadId
        ]
        OpenThread.restype = wintypes.HANDLE

        thread_handle = OpenThread(
            flag.thread.th32cs.THREAD_ALL_ACCESS,  # DWORD dwDesiredAccess
            False,                                  # BOOL  bInheritHandle
            wintypes.DWORD(self.id_),               # DWORD dwThreadId
        )
        if thread_handle is None:
            logger.error('Could not obtain a valid thread handle')
            raise ctypes.WinError()

        return thread_handle

    @property
    def context(self):
        # logger.debug(f'Get Thread Context')
        context = structure.thread.CONTEXT()
        context.ContextFlags = flag.thread.context.CONTEXT_FULL | flag.thread.context.CONTEXT_DEBUG_REGISTERS

        # https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getthreadcontext
        GetThreadContext = kernel32.GetThreadContext
        GetThreadContext.argtypes = [
            wintypes.HANDLE,                           # hThread
            ctypes.POINTER(structure.thread.CONTEXT),  # lpContext
        ]
        GetThreadContext.restype = wintypes.BOOL

        with self.handle() as thread_handle:
            result = GetThreadContext(
                thread_handle,
                ctypes.byref(context)
            )

        if not result:
            raise ctypes.WinError()

        return context


class ProcessThreads:
    def __init__(self, process):
        self._process = process
        self._snapshot = None

    def get_first_thread_info(self, process_snapshot):
        logger.debug('Get first thread info [kernel32.Thread32First]')

        thread_entry = structure.thread.THREADENTRY32()

        thread_entry.dwSize = ctypes.sizeof(thread_entry)

        # https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/nf-tlhelp32-thread32first
        Thread32First = kernel32.Thread32First
        Thread32First.argtypes = [
            wintypes.HANDLE,                                 # hSnapshot
            ctypes.POINTER(structure.thread.THREADENTRY32),  # lpte
        ]
        Thread32First.restype = wintypes.BOOL

        success = Thread32First(
            process_snapshot,
            ctypes.byref(thread_entry)
        )

        if not success:
            logger.error(f'Thread32First')
            raise ctypes.WinError()
        return thread_entry

    def get_next_thread_info(self, process_snapshot):
        logger.debug('Get next thread info [kernel32.Thread32Next]')

        Thread32Next = kernel32.Thread32Next
        Thread32Next.argtypes = [
            wintypes.HANDLE,                                 # hSnapshot
            ctypes.POINTER(structure.thread.THREADENTRY32),  # lpte
        ]
        Thread32Next.restype = wintypes.BOOL

        thread_entry = structure.thread.THREADENTRY32()
        thread_entry.dwSize = ctypes.sizeof(thread_entry)

        success = Thread32Next(
            process_snapshot,
            ctypes.byref(thread_entry)
        )
        if not success:
            logger.error(f'Thread32Next')
            raise ctypes.WinError()
        return thread_entry

    def _build_thread(self, thread_entry):
        process_thread = ProcessThread()
        process_thread.id_ = thread_entry.th32OwnerProcessID
        process_thread.process_id = thread_entry.th32ThreadID
        process_thread.priority = thread_entry.tpBasePri
        return process_thread

    def __iter__(self):
        logger.debug(f'Enumerate Threads')

        if self._snapshot is None:
            self._snapshot = Snapshot(self._process.id_)

        first = True

        with self._snapshot.get() as snapshot:
            while True:
                try:
                    if first:
                        first = False
                        thread_entry = self.get_first_thread_info(snapshot)
                    else:
                        thread_entry = self.get_next_thread_info(snapshot)
                except OSError as e:
                    if 'The operation completed successfully' in str(e):
                        break
                    else:
                        raise
                thread_process_id = thread_entry.th32OwnerProcessID
                if thread_process_id == self._process.id_:
                    yield self._build_thread(thread_entry)
