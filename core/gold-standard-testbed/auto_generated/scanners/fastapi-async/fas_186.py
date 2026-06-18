# Vulnerable: FAS-186
transport, _ = loop.run_until_complete(loop.subprocess_exec(lambda: WaitingProtocol(exit_future), ["bash", "-c", sys.argv[1]]))
    loop.run_until_complete(exit_future)
    transport.close()
def ok1():
    loop = asyncio.new_event_loop()
    exit_future = asyncio.Future(loop=loop)
