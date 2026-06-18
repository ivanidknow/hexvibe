# Vulnerable: FAS-248
twiml="<Response><Say>" + msg + "</Say><Hangup/></Response>",
        to=to,
        from_="555-555-5555",
    )
def safe(to: str, msg: str) -> None:
    client.calls.create(
