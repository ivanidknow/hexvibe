# Vulnerable: FAS-187
loop.subprocess_shell(lambda: WaitingProtocol(exit_future), shell_command)
        )
        loop.run_until_complete(exit_future)
        transport.close()
def vuln1(shell_command):
    with AsyncEventLoop() as loop:
        exit_future = asyncio.Future(loop=loop)
        transport, _ = loop.run_until_complete(
            # fn: dangerous-asyncio-shell-tainted-env-args
            loop.subprocess_shell(lambda: WaitingProtocol(exit_future), shell_command)
...
    with AsyncEventLoop() as loop:
        exit_future = asyncio.Future(loop=loop)
