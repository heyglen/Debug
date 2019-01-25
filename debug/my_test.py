import logging
import subprocess

import colorlog

import my_debugger

handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(levelname)-5s %(name)s %(message)s '))

logger = logging.getLogger('debugger.test')
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)


printf_exe = r'python "C:\Users\ghar\code\book\gray hat\printf_loop.py"'
process = subprocess.Popen(printf_exe, shell=True)
process_id = process.pid
# process_id = int(input('Enter the Process ID of the process to attach to: '))

debugger = my_debugger.debugger(process_id)

wprintf_function_address = debugger.get_function_address('msvcrt', 'wprintf')
# debugger.set_breakpoint(wprintf_function_address)

debugger.run()
# debugger.detach()

for thread in debugger.process.threads:
    # for thread in debugger.enumerate_threads():
    context = thread.context
    logger.debug(f'Thread {thread} Registers:')
    logger.debug(f'\tEIP: {context.Eip}')
    logger.debug(f'\tESP: {context.Esp}')
    logger.debug(f'\tEBP: {context.Ebp}')
    logger.debug(f'\tEAX: {context.Eax}')
    logger.debug(f'\tEBX: {context.Ebx}')
    logger.debug(f'\tECX: {context.Ecx}')
    logger.debug(f'\tEDX: {context.Edx}')
