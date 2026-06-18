// Vulnerable: VUL-CVE-2010-1156
return TRUE; /* matched without fuzzyness */

	/* matched with some fuzzyness .. check if there's an exact match
	   for some other nick in the same channel. */
        return nick_nfind(channel, msgstart, (int) (msg-msgstart)) == NULL;
}
