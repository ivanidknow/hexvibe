# Vulnerable: FAS-185
proc = loop.run_until_complete(asyncio.subprocess.create_subprocess_exec(program, [program, "-c", sys.argv[1]]))
    loop.run_until_complete(proc.communicate())
def ok1():
    program = "echo"
    loop = asyncio.new_event_loop()
