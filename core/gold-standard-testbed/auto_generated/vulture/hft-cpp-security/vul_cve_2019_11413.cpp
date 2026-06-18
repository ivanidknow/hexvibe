// Vulnerable: VUL-CVE-2019-11413
void js_RegExp_prototype_exec(js_State *J, js_Regexp *re, const char *text)
{
	int i;
	int opts;
...
	}

	if (!js_regexec(re->prog, text, &m, opts)) {
		js_newarray(J);
		js_pushstring(J, text);
...
...

	return !match(prog->start, sp, sp, prog->flags | eflags, sub);
}
