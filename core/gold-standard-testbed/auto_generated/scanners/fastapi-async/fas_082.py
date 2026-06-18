# Vulnerable: FAS-082
proc = loop.run_until_complete(asyncio.subprocess.create_subprocess_shell(event['cmd']))
        loop.run_until_complete(proc.wait())
def other_handler(event, context):
    shell_command = 'echo "Hello world"'
    with AsyncEventLoop() as loop:
        exit_future = asyncio.Future(loop=loop)
