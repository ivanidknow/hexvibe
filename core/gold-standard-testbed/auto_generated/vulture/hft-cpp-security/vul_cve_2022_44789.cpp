// Vulnerable: VUL-CVE-2022-44789
if (!ref->getter && !ref->setter) {
			js_pushvalue(J, ref->value);
			js_setproperty(J, -2, "value");
			js_pushboolean(J, !(ref->atts & JS_READONLY));
			js_setproperty(J, -2, "writable");
...
			js_setproperty(J, -2, "value");
			js_pushboolean(J, !(ref->atts & JS_READONLY));
			js_setproperty(J, -2, "writable");
		} else {
			if (ref->getter)
...
		hasvalue = 1;
		js_setproperty(J, -3, name);
	}
