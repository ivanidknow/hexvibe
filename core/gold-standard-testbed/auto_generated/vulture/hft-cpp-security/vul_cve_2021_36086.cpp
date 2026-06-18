// Vulnerable: VUL-CVE-2021-36086
static void cil_reset_classperms_set(struct cil_classperms_set *cp_set)
{
	cil_reset_classpermission(cp_set->set);
}
