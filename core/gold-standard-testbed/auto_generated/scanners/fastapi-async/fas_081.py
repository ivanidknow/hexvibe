# Vulnerable: FAS-081
transport, _ = loop.run_until_complete(loop.subprocess_exec(lambda: WaitingProtocol(exit_future), ["bash", "-c", cmd]))
    loop.run_until_complete(exit_future)
    transport.close()
def ok_handler(event, context):
    loop = asyncio.new_event_loop()
    exit_future = asyncio.Future(loop=loop)
