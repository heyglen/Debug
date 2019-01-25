import ctypes
import ctypes.util
from ctypes import wintypes
import itertools

from fastlogging import LogInit

from process import Process
from my_debugger_defines import (constant, structure, CONTEXT, CONTEXT_DEBUG_REGISTERS,
                                 CONTEXT_FULL, PROCESS_INFORMATION,
                                 TH32CS_SNAPTHREAD, THREAD_ALL_ACCESS,
                                 THREADENTRY32)


logger = LogInit(console=True, colors=True)
# handler = colorlog.StreamHandler()
# handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(levelname)-5s %(name)s %(message)s '))
# root_logger.setLevel(logging.DEBUG)
# root_logger.addHandler(handler)

# logger = logging.getLogger('debugger.debugger')
# logger.setLevel(logging.DEBUG)
# logger.addHandler(handler)

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)


class debugger:
    def __init__(self, process_id):
        self.process = Process(process_id)
        self.debugger_active = False
        self._event_count = 0

        self.thread_handle = None
        self.context = None

        self.breakpoints = dict()

        self.exception = None
        self.exception_address = None

    def set_breakpoint(self, address):
        logger.debug(f'Set Breakpoint @ {address:#016x}')
        if address not in self.breakpoints:
            try:
                # store the original byte
                original_byte = self.process.memory.read(address, length=1)
                logger.debug(f'Original byte stored')
                # Write INT3 opcode
                self.process.memory.write(address, b'\xCC')
                logger.debug(f'Interrupt 3 opcode written')
                # register the breakpoint in our internal list
                self.breakpoints[address] = (address, original_byte)
                logger.debug(f'Breakpoint stored')
            except Exception as e:
                logger.exception(f'Set Breakpoint Exception {str(e)}')
                return False
            return True

    def attach(self):
        logger.debug(f'Attach to process {self.process.name}[{self.process.id_}]')
        if kernel32.DebugActiveProcess(wintypes.DWORD(self.process.id_)):
            self.debugger_active = True
            # self.process_id = int(process_id)
            # self.run()
            # logger.debug(f'Attached to process')
        else:
            logger.debug(f'Unable to attach to the process')

    def run(self):
        # logger.debug(f'Run process')
        while self.debugger_active:
            self.get_debug_event()

    def get_debug_event(self):
        self._event_count += 1
        # logger.debug(f'Get debug event {self._event_count}')
        debug_event = structure.debug.DEBUG_EVENT()
        continue_status = constant.debug.continue_status.DBG_CONTINUE
        event = kernel32.WaitForDebugEvent(
            ctypes.byref(debug_event),
            constant.debug.continue_status.INFINITE,
        )
        if event:
            # self.debugger_active = False
            self.thread_handle = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(self.thread_handle)

            for name, value in itertools.zip_longest(constant.debug.event.__class__._fields, constant.debug.event):
                if value == debug_event.dwDebugEventCode:
                    logger.debug(f'Thread {debug_event.dwThreadId} Debug Event {name}[{value}]')
                    break

            # Examine Exceptions
            if debug_event.dwDebugEventCode == constant.debug.event.EXCEPTION_DEBUG_EVENT:
                debug_exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                if debug_exception == constant.debug.exception.EXCEPTION_ACCESS_VIOLATION:
                    logger.debug(f'Exception Access Violation Detected')
                elif debug_exception == constant.debug.exception.EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif debug_exception == constant.debug.exception.EXCEPTION_SINGLE_STEP:
                    logger.debug(f'Single Stepping')

            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status
            )

    def exception_handler_breakpoint(self):
        logger.debug(f'[*] Inside the breakpoint handler.')
        logger.debug(f'Exception Address {self.exception_address:#016x}')
        return constant.debug.continue_status.DBG_CONTINUE

    def detach(self):
        # logger.debug(f'Detach from process')
        stopped = kernel32.DebugActiveProcessStop(
            wintypes.DWORD(self.process_id)
        )
        if stopped:
            logger.debug(f'[*] Finished debugging. Exiting')
        else:
            logger.debug(f'There was an Error')
        return stopped

    def open_thread(self, thread_id):
        # logger.debug(f'Open thread {thread_id}')
        thread_handle = kernel32.OpenThread(
            THREAD_ALL_ACCESS,  # DWORD dwDesiredAccess
            False,              # BOOL  bInheritHandle
            wintypes.DWORD(thread_id),              # DWORD dwThreadId
        )
        if thread_handle is None:
            logger.error('Could not obtain a valid thread handle')
            return False
        return thread_handle

    def enumerate_threads(self):
        # logger.debug(f'Enumerate Threads')
        process_id = wintypes.DWORD(self.process_id)
        thread_entry = THREADENTRY32()
        threads = list()
        # https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
        snapshot = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPTHREAD,
            process_id,
        )
        if snapshot is None:
            # logger.debug(f'Snapshot failed')
            return False

        thread_entry.dwSize = ctypes.sizeof(thread_entry)
        success = kernel32.Thread32First(
            snapshot,
            ctypes.byref(thread_entry)
        )

        if not success:
            logger.debug(f'Unable to get first thread')

        while success:
            if thread_entry.th32OwnerProcessID == process_id.value:
                threads.append(
                    thread_entry.th32ThreadID
                )
            success = kernel32.Thread32Next(
                snapshot,
                ctypes.byref(thread_entry)
            )
        kernel32.CloseHandle(snapshot)

        return threads

    def get_thread_context(self, thread_id):
        # logger.debug(f'Get Thread Context')
        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        thread_handle = self.open_thread(thread_id)
        result = kernel32.GetThreadContext(
            thread_handle,
            ctypes.byref(context)
        )
        if not result:
            return False
        kernel32.CloseHandle(thread_handle)
        return context

    def func_resolve(self, dll, function):
        return self.get_function_address(dll, function)

    def get_function_address(self, dll, function):

        dll_location = ctypes.util.find_library(dll)

        GetModuleHandleW = kernel32.GetModuleHandleW
        GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        GetModuleHandleW.restype = wintypes.HMODULE

        module_handle = GetModuleHandleW(dll_location)
        if not module_handle:
            raise ctypes.WinError()
        logger.debug(f'{dll} @ {module_handle:#016x}')

        GetProcAddress = kernel32.GetProcAddress
        GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
        GetProcAddress.restype = ctypes.c_ulonglong

        function_address = GetProcAddress(module_handle, bytes(function.encode('ascii')))

        if not function_address:
            raise ctypes.WinError()
        logger.debug(f'{dll}.{function} @ {function_address:#016x}')
        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [wintypes.HMODULE]

        CloseHandle(module_handle)
        return function_address
