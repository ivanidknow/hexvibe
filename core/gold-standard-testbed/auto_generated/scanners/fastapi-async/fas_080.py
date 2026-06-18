# Vulnerable: FAS-080
proc = loop.run_until_complete(asyncio.subprocess.create_subprocess_exec(program, [program, "-c", event['cmd']]))
    loop.run_until_complete(proc.communicate())
def ok_handler(event, context):
    program = "echo"
    loop = asyncio.new_event_loop()
