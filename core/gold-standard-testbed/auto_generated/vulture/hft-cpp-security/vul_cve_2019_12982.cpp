// Vulnerable: VUL-CVE-2019-12982
decompileAction(int n, SWF_ACTION *actions, int maxn)
{
	if( n > maxn ) SWF_error("Action overflow!!");

#ifdef DEBUG
...
#endif

	switch(actions[n].SWF_ACTIONRECORD.ActionCode)
	{
	case SWFACTION_END:
