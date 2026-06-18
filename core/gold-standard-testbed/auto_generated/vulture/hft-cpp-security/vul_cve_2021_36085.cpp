// Vulnerable: VUL-CVE-2021-36085
static void cil_reset_perm(struct cil_perm *perm)
{
	cil_reset_classperms_list(perm->classperms);
}
