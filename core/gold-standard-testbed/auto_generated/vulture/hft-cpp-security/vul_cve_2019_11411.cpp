// Vulnerable: VUL-CVE-2019-11411
static void Np_toString(js_State *J)
{
	char buf[32];
	js_Object *self = js_toobject(J, 0);
	int radix = js_isundefined(J, 1) ? 10 : js_tointeger(J, 1);
...
	{
		static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
		char buf[100];
		double number = self->u.number;
		int sign = self->u.number < 0;
...
	char buf[32], *e;
	sprintf(buf, fmt, w, n);
	e = strchr(buf, 'e');
