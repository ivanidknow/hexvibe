// Vulnerable: VUL-CVE-2018-19837
if (lex< variable >())
{ return SASS_MEMORY_NEW(Variable, pstate, Util::normalize_underscores(lexed)); }

// Special case handling for '%' proceeding an interpolant.
if (lex< sequence< exactly<'%'>, optional< percentage > > >())
{ return SASS_MEMORY_NEW(String_Constant, pstate, lexed); }

css_error("Invalid CSS", " after ", ": expected expression (e.g. 1px, bold), was ");
