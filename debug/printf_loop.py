import ctypes
import time
import logging

import colorlog


handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(levelname)-5s %(name)s %(message)s '))

logger = logging.getLogger('debugger.wprintf_loop')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

counter = 0

new_line = '\n'

wprintf = ctypes.cdll.msvcrt.wprintf
# printf.argtypes = [ctypes.c_char_p]
wprintf.argtypes = [ctypes.c_wchar_p]

for _ in range(4):
    wprintf(f'wprintf loop # {counter}{new_line}')
    time.sleep(1)
    counter += 1
