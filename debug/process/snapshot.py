"""
"""

import contextlib
import logging
import ctypes
from ctypes import wintypes

from .constant import constant
from ..kernel32 import kernel32
from ..handle_resource import HandleResource

from .flag import flag


logger = logging.getLogger('debugger.process_snapshot')


class Snapshot(HandleResource):

    def __init__(self, process_id):
        self.id_ = process_id

    def _open(self):
        logger.debug('Open process snapshot [kernel32.CreateToolhelp32Snapshot]')
        # https://docs.microsoft.com/en-us/windows/desktop/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
        CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
        CreateToolhelp32Snapshot.argtypes = [
            wintypes.DWORD,  # dwFlags
            wintypes.DWORD,  # th32ProcessID
        ]
        CreateToolhelp32Snapshot.restype = wintypes.HANDLE

        snapshot_handle = kernel32.CreateToolhelp32Snapshot(
            flag.thread.th32cs.TH32CS_SNAPTHREAD,
            self.id_,
        )

        if snapshot_handle == constant.handle.INVALID_HANDLE_VALUE:
            logger.error('CreateToolhelp32Snapshot')
            raise ctypes.WinError()
        return snapshot_handle

    @contextlib.contextmanager
    def get(self):
        handle = self._open()
        yield handle
        self._close(handle)
