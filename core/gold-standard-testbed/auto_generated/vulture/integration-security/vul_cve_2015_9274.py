# Vulnerable: VUL-CVE-2015-9274
{
    TRACE_DISPATCH (this, u.format);
    if (unlikely (!c->may_dispatch (this, &u.format))) TRACE_RETURN (c->default_return_value ());
    switch (u.format) {
    case 1: return TRACE_RETURN (c->dispatch (u.format1));
...
  {
    TRACE_DISPATCH (this, u.format);
    if (unlikely (!c->may_dispatch (this, &u.format))) TRACE_RETURN (c->default_return_value ());
    switch (u.format) {
    case 1: return TRACE_RETURN (c->dispatch (u.format1));
...
    if (unlikely (!c->may_dispatch (this, &u.format))) TRACE_RETURN (c->default_return_value ());
    switch (u.format) {
    case 1: return TRACE_RETURN (u.format1.dispatch (c));
