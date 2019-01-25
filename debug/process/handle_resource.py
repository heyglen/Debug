"""
ABC for anything that gets open handles
"""

import abc
import ctypes
from ctypes import wintypes
import logging

from .kernel32 import kernel32


logger = logging.getLogger(__name__)


class HandleResource(abc.ABC):

    def _close(self, thread_handle):
        logger.debug(f'Close Handle [kernel32.CloseHandle]')
        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [
            wintypes.HANDLE  # hObject
        ]
        CloseHandle.restype = wintypes.BOOL

        result = CloseHandle(thread_handle)
        if not result:
            raise ctypes.WinError()
        return True
