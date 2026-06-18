// Vulnerable: VUL-CVE-2019-11412
cstm(J, F, catchstm);
	emit(J, F, OP_ENDCATCH);
	L3 = emitjump(J, F, OP_JUMP); /* skip past the try block to the finally block */
}
