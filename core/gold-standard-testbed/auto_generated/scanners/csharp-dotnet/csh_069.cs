// Vulnerable: CSH-069
_LOG.Info($"Processed {position} in {elapsedMs:000} ms.");
}
public static void NotLogging()
{
    // System.Web.TraceContext.Warn does not support structured logging
    var traceContext = new FakeTraceContext();
