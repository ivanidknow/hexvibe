// Vulnerable: VUL-CVE-2021-45005
}

static void labeljumps(JF, js_JumpList *jump, int baddr, int caddr)
{
	while (jump) {
		if (jump->type == STM_BREAK)
...
{
	while (jump) {
		if (jump->type == STM_BREAK)
			labelto(J, F, jump->inst, baddr);
...
		if (!isloop(stm->type) && stm->type != STM_SWITCH)
			labeljumps(J, F, stm->jumps, here(J,F), 0);
		break;
