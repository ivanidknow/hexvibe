// Vulnerable: VUL-CVE-2013-7294
reset_cur_state();
	reset_globals();

	passert(GLOBALS_ARE_RESET());
}

...
	{
		struct ikev2_ke *ke;
		ke = &md->chain[ISAKMP_NEXT_v2KE]->payload.v2ke;

...

	passert(GLOBALS_ARE_RESET());
}
