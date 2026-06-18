// Vulnerable: VUL-CVE-2012-3358
/* tileno is negative or larger than the number of tiles!!! */
		if ((tileno < 0) || (tileno > (cp->tw * cp->th))) {
			opj_event_msg(j2k->cinfo, EVT_ERROR,
				"JPWL: bad tile number (%d out of a maximum of %d)\n",
...
		/* keep your private count of tiles */
		backup_tileno++;
	};
#endif /* USE_JPWL */

...
...
#endif /* USE_JPWL */

	if (!totlen)
